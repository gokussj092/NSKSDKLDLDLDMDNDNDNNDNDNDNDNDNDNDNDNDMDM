#!/usr/bin/env python3
"""Synthetic continuous JSON viewer checks; no provider access or user data."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
CPP = ROOT / 'android/app/src/main/cpp'
JAVA = ROOT / 'android/app/src/main/java/com/ghostdeveloper/spdecode'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jni-include', type=Path, required=True)
    parser.add_argument('--cache', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    report = {'syntheticOnly': True, 'androidDeviceTestsRun': False, 'checks': []}

    def run(name, command, env=None):
        start = time.monotonic()
        result = subprocess.run([str(x) for x in command], cwd=ROOT, env=env,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=180)
        report['checks'].append({'name': name, 'exitCode': result.returncode,
                                 'seconds': round(time.monotonic() - start, 3), 'output': result.stdout[-12000:]})
        print(f'{name}: {"PASS" if result.returncode == 0 else "FAIL"}', flush=True)
        if result.returncode:
            raise RuntimeError(result.stdout)

    try:
        with tempfile.TemporaryDirectory(prefix='continuous-json-') as directory:
            temp = Path(directory)
            for fixture in ['result_engine_test', 'result_lines_test']:
                binary = temp / fixture
                run(fixture + '_compile', ['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror',
                    '-g', '-O1', '-fsanitize=address,undefined', '-fno-omit-frame-pointer',
                    '-I', CPP, CPP / 'result_engine.cpp', ROOT / f'tests/native/{fixture}.cpp', '-o', binary])
                env = os.environ.copy()
                env['ASAN_OPTIONS'] = 'detect_leaks=0'
                run(fixture + '_asan_ubsan', [binary], env)
            library = temp / 'libspdecode_result_engine.so'
            run('jni_compile', ['g++', '-std=c++17', '-Wall', '-Wextra', '-Werror', '-shared', '-fPIC',
                '-I', args.jni_include, '-I', args.jni_include / 'linux',
                CPP / 'result_engine.cpp', CPP / 'result_engine_jni.cpp', '-o', library])
            run('jni_contract', ['java', ROOT / 'tests/native/result_engine_jni/NativeResultEngine.java', library])
            files = [JAVA / file for file in ['ContinuousJsonView.kt', 'JsonTreeViewer.kt',
                     'LargeResultViewer.kt', 'results/NativeResultEngine.kt']]
            files += [ROOT / 'android/app/src/androidTest/java/com/ghostdeveloper/spdecode' / file
                      for file in ['JsonTreeViewerInstrumentedTest.kt', 'SingleResultViewInstrumentedTest.kt']]
            run('kotlin_syntax', [sys.executable, ROOT / 'scripts/qa/kotlin_syntax.py', '--cache', args.cache, *files])
            # Compile the actual Kotlin JNI wrapper against its real JSON dependency.
            stub = temp / 'Keep.kt'
            stub.write_text('package androidx.annotation\nannotation class Keep\n')
            cp = ':'.join(str(p) for p in sorted(args.cache.glob('*.jar')))
            run('kotlin_jni_wrapper_compile', ['java', '-cp', cp, 'org.jetbrains.kotlin.cli.jvm.K2JVMCompiler',
                '-no-stdlib', '-no-reflect', '-classpath', cp, '-d', temp / 'classes',
                stub, JAVA / 'results/NativeResultEngine.kt'])
        report['status'] = 'HOST_PASSED_ANDROID_DEVICE_PENDING'
    finally:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + '\n')


if __name__ == '__main__':
    main()
