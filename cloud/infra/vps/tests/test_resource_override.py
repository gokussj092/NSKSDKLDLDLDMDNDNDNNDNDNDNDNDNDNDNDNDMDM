"""Exercise the real Compose argument builders without contacting a Docker host."""
from pathlib import Path
import importlib.util
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

VPS = Path(__file__).resolve().parents[1]
SHELLS = ("spdecodectl", "install.sh", "resume-install.sh", "resume-services.sh")
HELPERS = ("qa-test.py", "panel-reset.py", "provider-services.py")


class ResourceOverrideTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="spdecode resources ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cfg = self.root / "protected config"
        self.cfg.mkdir()
        self.env = self.cfg / "cloud.env"
        self.env.write_text("CLOUD_WORKER_TOKEN=synthetic-secret-never-printed\n")
        self.resource = self.cfg / "compose.resources.yaml"
        self.repo = self.root / "repo"
        (self.repo / "cloud").mkdir(parents=True)
        self.base = self.repo / "cloud/compose.yaml"
        self.base.write_text("services: {}\n")

    def write_override(self):
        self.resource.write_text("services:\n  decoder-worker:\n    mem_limit: 4g\n    cpus: 4.0\n")
        self.resource.chmod(0o600)

    def shell(self, name, operations=None):
        source = (VPS / name).read_text()
        if name == "spdecodectl":
            body = source[source.index("compose(){"):source.index("\npreflight(){")]
            body += "\n" + (operations or 'compose --profile commerce up -d --no-deps web')
        else:
            start = source.index("compose=(docker compose")
            end = source.index('\n"${compose[@]}" config --quiet', start)
            body = source[start:end].replace("/etc/spdecode/cloud.env", shlex.quote(str(self.env)))
            body = body.replace("/etc/spdecode/compose.resources.yaml", shlex.quote(str(self.resource)))
            body += '\n"${compose[@]}" --profile commerce up -d --no-deps web'
        script = "set -euo pipefail\n"
        for key, value in (("CFG", self.cfg), ("REPO", self.repo), ("ENVFILE", self.env)):
            script += key + "=" + shlex.quote(str(value)) + "\n"
        script += 'die(){ echo "override rejected" >&2; exit 41; }; fail(){ die; };\n'
        script += "docker(){ printf '%s\\0' \"$@\" __CALL_END__; };\n" + body
        return subprocess.run(["bash", "-c", script], cwd=self.repo,
                              capture_output=True, timeout=10)

    def calls(self, result):
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        values = result.stdout.decode().split("\0")[:-1]
        calls, current = [], []
        for value in values:
            if value == "__CALL_END__":
                calls.append(current)
                current = []
            else:
                current.append(value)
        return calls

    def test_every_shell_uses_override_after_base_without_changing_it(self):
        self.write_override()
        before = self.resource.read_bytes()
        for name in SHELLS:
            with self.subTest(script=name):
                call = self.calls(self.shell(name))[0]
                files = [call[i + 1] for i, arg in enumerate(call) if arg == "-f"]
                self.assertEqual(len(files), 2)
                self.assertEqual(files[1], str(self.resource))
                self.assertEqual(call[-6:], ["--profile", "commerce", "up", "-d", "--no-deps", "web"])
                self.assertNotIn("apk-qa", call)
                self.assertNotIn("synthetic-secret-never-printed", repr(call))
        self.assertEqual(self.resource.read_bytes(), before)
        self.assertEqual(self.resource.stat().st_mode & 0o777, 0o600)

    def test_every_shell_remains_compatible_without_override(self):
        for name in SHELLS:
            with self.subTest(script=name):
                call = self.calls(self.shell(name))[0]
                self.assertEqual(call.count("-f"), 1)

    def test_every_shell_rejects_directory_or_dangling_link_before_docker(self):
        for kind in ("directory", "dangling-link"):
            if kind == "directory":
                self.resource.mkdir()
            else:
                self.resource.symlink_to(self.cfg / "missing-target")
            for name in SHELLS:
                with self.subTest(script=name, kind=kind):
                    result = self.shell(name)
                    self.assertEqual(result.returncode, 41)
                    self.assertEqual(result.stdout, b"")
            self.resource.rmdir() if kind == "directory" else self.resource.unlink()

    def test_cli_keeps_external_override_when_update_or_rollback_changes_checkout(self):
        self.write_override()
        replacement = self.root / "previous revision"
        replacement.mkdir()
        operation = 'compose build web\nREPO=' + shlex.quote(str(replacement))
        operation += '\ncompose up -d --no-deps web'
        calls = self.calls(self.shell("spdecodectl", operation))
        self.assertEqual(len(calls), 2)
        for call in calls:
            files = [call[i + 1] for i, arg in enumerate(call) if arg == "-f"]
            self.assertEqual(files[1], str(self.resource))
        self.assertNotEqual(calls[0][calls[0].index("-f") + 1],
                            calls[1][calls[1].index("-f") + 1])

    def load_helper(self, name):
        spec = importlib.util.spec_from_file_location("resource_test_" + name.replace("-", "_"), VPS / name)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.ENV = self.env
        return module

    def test_cli_backup_preserves_resources_and_private_permissions(self):
        self.write_override()
        conf = self.cfg / "install.conf"
        conf.write_text("SPDECODE_REF=patch/20-apps\n")
        source = (VPS / "spdecodectl").read_text()
        body = source.split("\n backup)\n", 1)[1].split(";;", 1)[0]
        script = "set -euo pipefail\numask 077\n"
        for key, value in (("ROOT", self.root), ("CFG", self.cfg), ("CONF", conf),
                           ("REPO", self.repo), ("ENVFILE", self.env)):
            script += key + "=" + shlex.quote(str(value)) + "\n"
        script += 'git(){ printf "%040d\\n" 1; }; log(){ :; };\n' + body
        result = subprocess.run(["bash", "-c", script], capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        copies = list((self.root / "backups").glob("resources-*.yaml"))
        self.assertEqual(len(copies), 1)
        self.assertEqual(copies[0].read_bytes(), self.resource.read_bytes())
        self.assertEqual(copies[0].stat().st_mode & 0o777, 0o600)
        self.assertEqual(result.stdout, b"")

    def test_python_recreation_helpers_use_same_protected_override(self):
        self.write_override()
        for name in HELPERS:
            with self.subTest(script=name):
                module = self.load_helper(name)
                if name == "qa-test.py":
                    with mock.patch.object(module, "run") as runner:
                        module.compose("up", "-d", "--no-deps", "web")
                    command = list(runner.call_args.args)
                elif name == "panel-reset.py":
                    with mock.patch.object(module, "invoke") as runner:
                        module.compose("up", "-d", "--no-deps", "web")
                    command = runner.call_args.args[0]
                else:
                    with mock.patch.object(module.subprocess, "run") as runner:
                        module.compose("up", "-d", "--no-deps", "web")
                    command = runner.call_args.args[0]
                self.assertEqual(command.count("-f"), 2)
                self.assertEqual(command[-6:], ["-f", str(self.resource), "up", "-d", "--no-deps", "web"])
                self.assertNotIn("synthetic-secret-never-printed", repr(command))

    def test_python_builder_is_compatible_without_override_and_rejects_bad_path(self):
        module = self.load_helper("qa-test.py")
        with mock.patch.object(module, "run") as runner:
            module.compose("ps")
        self.assertEqual(runner.call_args.args.count("-f"), 1)
        self.resource.mkdir()
        with mock.patch.object(module, "run") as runner:
            with self.assertRaises(RuntimeError):
                module.compose("up", "-d", "web")
            runner.assert_not_called()


if __name__ == "__main__":
    unittest.main()
