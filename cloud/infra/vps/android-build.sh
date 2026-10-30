#!/usr/bin/env bash
# Builds signed TESTING APK/AAB using the permanent Play upload key.
# It does not publish to Google Play or claim production approval.
set -Eeuo pipefail
umask 077
ROOT="${SPDECODE_HOME:-/opt/spdecode}"
CFG="${SPDECODE_CONFIG_DIR:-/etc/spdecode}"
REPO="$ROOT/repo"
SIGN="$CFG/signing.env"
SDK="$ROOT/android-sdk"
GRADLE="$ROOT/gradle/gradle-8.11.1/bin/gradle"
fail(){ echo "ERROR: $*" >&2; exit 1; }
log(){ echo "[spdecode android] $*"; }
[[ $(id -u) -eq 0 ]] || fail "sudo/root required"
[[ -d "$REPO/.git" ]] || fail "Install Cloud VPS first"
# Android NDK and Gradle distributions for this repo require a Linux x86_64 build host.
setup(){
  [[ $(uname -m) == x86_64 ]] || fail "Android SDK/NDK host is x86_64-only here. Build using GitHub Actions on ARM64 VPS."
  apt-get update
  DEBIAN_FRONTEND=noninteractive apt-get install -y openjdk-17-jdk unzip curl python3
  local available
  available=$(df -Pk "$ROOT" | awk 'NR==2 {print $4}')
  ((available>12582912)) || fail "Need at least 12 GiB free to provision Android SDK, NDK and Gradle"
  mkdir -p "$SDK/cmdline-tools" "$ROOT/gradle"
  if [[ ! -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ]]; then
    local archive tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' RETURN
    archive="$tmp/cmdline-tools.zip"
    curl -fSL --retry 3 --output "$archive" \
      https://dl.google.com/android/repository/commandlinetools-linux-13114758_latest.zip
    printf '7ec965280a073311c339e571cd5de778b9975026cfcbe79f2b1cdcb1e15317ee  %s\n' "$archive" | sha256sum -c -
    unzip -q "$archive" -d "$tmp/unpack"
    mkdir -p "$SDK/cmdline-tools/latest"
    cp -a "$tmp/unpack/cmdline-tools/." "$SDK/cmdline-tools/latest/"
  fi
  if [[ ! -x "$GRADLE" ]]; then
    local zip tmp
    tmp=$(mktemp -d)
    trap 'rm -rf "$tmp"' RETURN
    zip="$tmp/gradle.zip"
    curl -fSL --retry 3 --output "$zip" \
      https://services.gradle.org/distributions/gradle-8.11.1-bin.zip
    local sha
    sha=$(curl -fsSL https://services.gradle.org/distributions/gradle-8.11.1-bin.zip.sha256)
    [[ "$sha" =~ ^[0-9a-fA-F]{64}$ ]] || fail "Invalid Gradle SHA256 response"
    printf '%s  %s\n' "$sha" "$zip" | sha256sum -c -
    unzip -q "$zip" -d "$ROOT/gradle"
  fi
  export ANDROID_HOME="$SDK" ANDROID_SDK_ROOT="$SDK"
  export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
  local manager="$SDK/cmdline-tools/latest/bin/sdkmanager"
  yes | "$manager" --sdk_root="$SDK" --licenses >/dev/null || true
  "$manager" --sdk_root="$SDK" \
    "platforms;android-36" "build-tools;35.0.0" \
    "cmake;3.22.1" "ndk;27.2.12479018" "platform-tools"
  "$GRADLE" --version >/dev/null
  log "Android toolchain ready. No signing key was generated."
}
signing_configure(){
  [[ $# -eq 2 ]] || fail "Usage: spdecode android signing configure /path/existing.p12 ALIAS"
  local input="$1" alias="$2" a b
  [[ -f "$input" && "$alias" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || fail "Invalid keystore path or alias"
  [[ $(stat -c %a "$input") =~ ^(400|600)$ ]] || fail "chmod 600 your keystore before provisioning"
  read -r -s -p "Keystore password (not echoed): " a </dev/tty; echo
  read -r -s -p "Key password (not echoed, Enter if same): " b </dev/tty; echo
  [[ -n "$a" ]] || fail "Empty keystore password"
  b="${b:-$a}"
  export SPDECODE_RELEASE_STORE_PASSWORD="$a" SPDECODE_RELEASE_KEY_PASSWORD="$b"
  command -v keytool >/dev/null || fail "Install Java 17 with spdecode android setup first"
  keytool -list -storetype PKCS12 -keystore "$input" \
    -storepass:env SPDECODE_RELEASE_STORE_PASSWORD -alias "$alias" >/dev/null ||
      fail "Invalid keystore/password/alias"
  install -d -m 0700 "$CFG/keys"
  local dst="$CFG/keys/upload-key.p12"
  if [[ "$input" != "$dst" ]]; then install -m 0600 "$input" "$dst"; fi
  export SPDECODE_RELEASE_STORE_FILE="$dst" SPDECODE_RELEASE_KEY_ALIAS="$alias"
  printf 'SPDECODE_RELEASE_STORE_FILE=%q\nSPDECODE_RELEASE_KEY_ALIAS=%q\nSPDECODE_RELEASE_STORE_PASSWORD=%q\nSPDECODE_RELEASE_KEY_PASSWORD=%q\n' \
    "$dst" "$alias" "$a" "$b" > "$SIGN"
  chmod 600 "$SIGN"
  unset a b SPDECODE_RELEASE_STORE_PASSWORD SPDECODE_RELEASE_KEY_PASSWORD
  log "Permanent upload key imported; back it up encrypted OFF the VPS."
  log "Check the upload certificate against Play Console before building updates."
}
signing_generate(){
  [[ $# -eq 1 ]] || fail "Usage: spdecode android signing generate ALIAS"
  local alias="$1" a b
  [[ "$alias" =~ ^[A-Za-z0-9_.-]{1,64}$ ]] || fail "Invalid alias"
  [[ ! -f "$CFG/keys/upload-key.p12" && ! -f "$SIGN" ]] ||
    fail "Existing upload key found: never regenerate keys for upgrades"
  read -r -s -p "New upload key password (>=12 chars): " a </dev/tty; echo
  ((${#a}>=12)) || fail "Password too short"
  export SPDECODE_RELEASE_STORE_PASSWORD="$a"
  install -d -m 0700 "$CFG/keys"
  keytool -genkeypair -storetype PKCS12 -keystore "$CFG/keys/upload-key.p12" \
    -storepass:env SPDECODE_RELEASE_STORE_PASSWORD \
    -keypass:env SPDECODE_RELEASE_STORE_PASSWORD \
    -alias "$alias" -keyalg RSA -keysize 4096 -validity 10000 \
    -dname "CN=SP-DECODE Upload,O=Ghost Developer"
  chmod 600 "$CFG/keys/upload-key.p12"
  printf 'SPDECODE_RELEASE_STORE_FILE=%q\nSPDECODE_RELEASE_KEY_ALIAS=%q\nSPDECODE_RELEASE_STORE_PASSWORD=%q\nSPDECODE_RELEASE_KEY_PASSWORD=%q\n' \
    "$CFG/keys/upload-key.p12" "$alias" "$a" "$a" > "$SIGN"
  chmod 600 "$SIGN"
  unset a SPDECODE_RELEASE_STORE_PASSWORD
  log "NEW upload key created for an app not previously signed. Back it up securely."
  log "For an existing Play Store app, register this upload certificate before updates."
}
build(){
  local version="" code="" testing=false qa=false
  while (($#)); do
    case "$1" in
      --version-name) version="$2";shift 2;;
      --version-code) code="$2";shift 2;;
      --testing-only) testing=true;shift;;
      --qa) qa=true;shift;;
      *) fail "Unknown Android build argument: $1";;
    esac
  done
  [[ "$testing" == true ]] || fail "C7/C8 production gate is BLOCKED. For signed closed-test artifacts pass --testing-only."
  [[ "$version" =~ ^[1-9][0-9]*\.[0-9]+\.[0-9]+$ &&
     "$code" =~ ^[1-9][0-9]*$ ]] || fail "Provide valid --version-name X.Y.Z and --version-code NUMBER"
  [[ -f "$SIGN" && $(stat -c %a "$SIGN") == 600 ]] || fail "Signing key missing: spdecode android signing configure..."
  [[ -x "$GRADLE" && -x "$SDK/cmdline-tools/latest/bin/sdkmanager" ]] || fail "Run spdecode android setup first"
  [[ -f "$CFG/api-domain" ]] || fail "Missing dedicated HTTPS API domain. Upgrade VPS installer first."
  local domain
  domain=$(cat "$CFG/api-domain")
  [[ "$domain" =~ ^[A-Za-z0-9.-]+$ && "$domain" == api.* ]] ||
    fail "Invalid dedicated Android API domain"
  python3 "$REPO/scripts/cloud_c7_release_gate.py" --stage
  local basecode
  basecode=$(sed -nE 's/.*versionCode = ([0-9]+).*/\1/p' "$REPO/android/app/build.gradle.kts")
  [[ "$basecode" =~ ^[0-9]+$ && $code -gt $basecode ]] ||
    fail "VersionCode must exceed current source ($basecode). Verify Play Console highest uploaded code too."
  local buildroot source sha
  buildroot=$(mktemp -d "$ROOT/builds/android-candidate.XXXXXX")
  source="$buildroot/source"
  sha=$(git -C "$REPO" rev-parse HEAD)
  git -C "$REPO" worktree add --detach "$source" "$sha" >/dev/null
  cleanup(){
    git -C "$REPO" worktree remove --force "$source" >/dev/null 2>&1 || true
    rm -rf "$buildroot"
  }
  trap cleanup EXIT
  python3 - "$source/android/app/build.gradle.kts" "$version" "$code" <<'PY'
import pathlib,re,sys
p=pathlib.Path(sys.argv[1]);data=p.read_text()
data,n=re.subn(r'versionCode = \d+', 'versionCode = '+sys.argv[3],data)
if n!=1:raise SystemExit("Invalid versionCode source")
data,m=re.subn(r'versionName = "[^"]+"','versionName = "'+sys.argv[2]+'"',data)
if m!=1:raise SystemExit("Invalid versionName source")
p.write_text(data)
PY
  # Root-owned signing config is intentionally separate from git worktrees.
  # shellcheck source=/dev/null
  source "$SIGN"
  export SPDECODE_RELEASE_STORE_FILE SPDECODE_RELEASE_STORE_PASSWORD
  export SPDECODE_RELEASE_KEY_ALIAS SPDECODE_RELEASE_KEY_PASSWORD
  export SPDECODE_CLOUD_API_BASE_URL="https://$domain" SPDECODE_CLOUD_RELEASE=true
  if [[ "$qa" == true ]]; then
    export SPDECODE_CLOUD_QA_BUILD=true
  else
    unset SPDECODE_CLOUD_QA_BUILD
  fi
  export ANDROID_HOME="$SDK" ANDROID_SDK_ROOT="$SDK"
  export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
  SPDECODE_TRUSTED_SIGNER_SHA256=$(keytool -exportcert -storetype PKCS12 \
    -keystore "$SPDECODE_RELEASE_STORE_FILE" \
    -storepass:env SPDECODE_RELEASE_STORE_PASSWORD \
    -alias "$SPDECODE_RELEASE_KEY_ALIAS" | sha256sum | awk '{print $1}')
  export SPDECODE_TRUSTED_SIGNER_SHA256
  log "Building Cloud-only signed APK/AAB candidate $version ($code) from $sha"
  (cd "$source/android" && "$GRADLE" --no-daemon :app:assembleRelease :app:bundleRelease)
  local apk="$source/android/app/build/outputs/apk/release/app-release.apk"
  local aab="$source/android/app/build/outputs/bundle/release/app-release.aab"
  [[ -s "$apk" && -s "$aab" ]] || fail "Gradle did not produce both APK and AAB"
  local tools="$SDK/build-tools/35.0.0"
  "$tools/apksigner" verify --verbose --print-certs "$apk" >/dev/null ||
    fail "APK signature invalid"
  "$tools/zipalign" -c -P 16 -v 4 "$apk" >/dev/null ||
    fail "APK has invalid alignment"
  jarsigner -verify -certs "$aab" | grep -q 'jar verified' ||
    fail "AAB upload signature invalid"
  python3 "$source/tests/cloud_c5_apk_audit.py" "$apk"
  local dest="$ROOT/artifacts/v$version-$code"
  [[ ! -e "$dest" ]] || fail "Artifact version already exists. Never overwrite signed releases."
  mkdir -p "$dest"
  cp "$apk" "$dest/SP-DECODE-v$version-$code-cloud-test.apk"
  cp "$aab" "$dest/SP-DECODE-v$version-$code-play-upload-test.aab"
  (cd "$dest" && sha256sum *.apk *.aab > SHA256SUMS.txt)
  printf 'version=%s\ncode=%s\nsource=%s\norigin=https://%s\nchannel=testing-only\nsigner_cert_sha256=%s\n' \
    "$version" "$code" "$sha" "$domain" "$SPDECODE_TRUSTED_SIGNER_SHA256" \
    > "$dest/BUILD-MANIFEST.txt"
  if [[ "$qa" == true ]]; then
    printf 'qa_build=true\nplay_integrity_required_for_qa=false\n' >> "$dest/BUILD-MANIFEST.txt"
  fi
  chmod -R go-rwx "$dest"
  log "Signed testing artifacts: $dest"
  log "AAB is for Google Play Console (closed testing); APK is for local testing."
  log "No upload or public production release was performed."
}
case "${1:-help}" in
  setup) setup;;
  signing)
    case "${2:-}" in
      configure) [[ $# -eq 4 ]] || fail "signing configure FILE ALIAS";signing_configure "$3" "$4";;
      generate) [[ $# -eq 3 ]] || fail "signing generate ALIAS";signing_generate "$3";;
      *) fail "signing configure FILE ALIAS | signing generate ALIAS";;
    esac;;
  build) shift;build "$@";;
  artifacts) ls -lah "$ROOT/artifacts" 2>/dev/null || log "No build artifacts yet";;
  help|--help|-h) echo "spdecode android setup|signing configure FILE ALIAS|signing generate ALIAS|build --version-name X.Y.Z --version-code N --testing-only [--qa]|artifacts";;
  *) fail "Unknown Android command";;
esac
