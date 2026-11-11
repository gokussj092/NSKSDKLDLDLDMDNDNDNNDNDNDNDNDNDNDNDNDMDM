#!/usr/bin/env bash
# Opt-in PUBLIC APK publisher, independent of the testing-only APK/AAB flow.
# Verify successful GitHub Actions from this exact source commit, build locally
# with the persistent signer, audit the binary, then switch one atomic pointer.
set -Eeuo pipefail
umask 077
ROOT="${SPDECODE_HOME:-/opt/spdecode}"
CFG="${SPDECODE_CONFIG_DIR:-/etc/spdecode}"
REPO="$ROOT/repo"
SDK="$ROOT/android-sdk"
GRADLE="$ROOT/gradle/gradle-8.11.1/bin/gradle"
SIGN="$CFG/signing.env"
PUBLISH="$REPO/cloud/infra/vps/apk-publication.py"
PUBLIC="${SPDECODE_PUBLIC_APK_DIR:-$ROOT/public-apks}"
PROJECT="gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM"
die(){ echo "[spdecode-apk] ERROR: $*" >&2;exit 1; }
log(){ echo "[spdecode-apk] $*"; }
[[ $(id -u) -eq 0 ]] || die "Requires root"
[[ -d "$REPO/.git" && -f "$PUBLISH" ]] || die "Update the SP-DECODE VPS source first"
CHANNEL="${1:-}"
case "$CHANNEL" in online|offline) ;; *) die "Usage: spdecode android public-build online|offline --ci-run ID | public-status online|offline | public-rollback online|offline";; esac
MODE="${2:-}"
case "$MODE" in
 --status)
   exec python3 "$PUBLISH" status "$CHANNEL" --root "$PUBLIC";;
 --rollback)
   mkdir -p "$ROOT/locks"
   exec 9>"$ROOT/locks/public-apk-build.lock"
   flock -n 9 || die "Another APK operation is running"
   exec python3 "$PUBLISH" rollback "$CHANNEL" --root "$PUBLIC";;
 --ci-run)
   [[ "${3:-}" =~ ^[1-9][0-9]{5,19}$ && $# -eq 3 ]] || die "Provide a GitHub Actions run ID"
   RUN="$3";;
 *) die "Usage: public-build CHANNEL --ci-run ID";;
esac
[[ $(uname -m) == x86_64 ]] || die "Android toolchain requires x86_64; use GitHub Actions for other architectures"
[[ -x "$GRADLE" && -x "$SDK/build-tools/35.0.0/apksigner" && -x "$SDK/build-tools/35.0.0/aapt" ]] ||
  die "Run spdecode android setup first"
[[ -f "$SIGN" && $(stat -c %a "$SIGN") == 600 ]] || die "Configure existing permanent signer first"
command -v gh >/dev/null || die "Install GitHub CLI and authenticate to read GitHub Actions runs"
command -v flock >/dev/null || die "flock is required"
mkdir -p "$ROOT/locks" "$ROOT/builds" "$PUBLIC"
exec 9>"$ROOT/locks/public-apk-build.lock"
flock -n 9 || die "Another APK build/publication is running"
[[ $(df -Pk "$ROOT" | awk 'NR==2{print $4}') -ge 10485760 ]] ||
  die "At least 10 GiB of free disk is required before a release build"
SOURCE_SHA=$(git -C "$REPO" rev-parse HEAD)
[[ "$SOURCE_SHA" =~ ^[0-9a-f]{40}$ ]] || die "Invalid source commit"
[[ -z $(git -C "$REPO" status --porcelain) ]] || die "Source worktree must be clean"
RUN_JSON=$(gh api "repos/$PROJECT/actions/runs/$RUN" --jq '{name,head_sha,head_branch,status,conclusion}')
EXPECTED_WORKFLOW="SP-DECODE Branch Release APK Signed"
[[ "$CHANNEL" == offline ]] && EXPECTED_WORKFLOW="SP-DECODE Offline Native APK (unified branch, persistent signer)"
RUN_JSON="$RUN_JSON" SOURCE_SHA="$SOURCE_SHA" EXPECTED_WORKFLOW="$EXPECTED_WORKFLOW" python3 - <<'PY' ||
import json,os,sys
try:
 r=json.loads(os.environ['RUN_JSON'])
 assert r['name']==os.environ['EXPECTED_WORKFLOW']
 assert r['head_sha']==os.environ['SOURCE_SHA']
 assert r['head_branch']=='feat/nuevas-integraciones'
 assert r['status']=='completed' and r['conclusion']=='success'
except (KeyError,AssertionError,ValueError):
 print("GitHub Actions was not successful for this exact commit and channel",file=sys.stderr)
 sys.exit(1)
PY
  die "GitHub Actions verification failed"
EXPECTED_ARTIFACT="SP-DECODE-BRANCH-APK-RELEASE-SIGNED"
[[ "$CHANNEL" == offline ]] && EXPECTED_ARTIFACT="SP-DECODE-OFFLINE-PERSISTENT-SIGNED-QA"
gh api "repos/$PROJECT/actions/runs/$RUN/artifacts" --jq '.artifacts[].name' |
  grep -Fxq "$EXPECTED_ARTIFACT" ||
  die "GitHub Actions run succeeded but has no verified signed APK artifact"
log "Verified signed release CI and artifact for $CHANNEL at $SOURCE_SHA"
# The existing VPS signing.env contains a protected shell-escaped PKCS12 path
# and passwords. Never read it from the source tree or log its values.
# shellcheck source=/dev/null
source "$SIGN"
export SPDECODE_RELEASE_STORE_FILE SPDECODE_RELEASE_STORE_PASSWORD
export SPDECODE_RELEASE_KEY_ALIAS SPDECODE_RELEASE_KEY_PASSWORD
[[ -f "$SPDECODE_RELEASE_STORE_FILE" ]] || die "Persistent signing key missing"
export SPDECODE_TRUSTED_SIGNER_SHA256
SPDECODE_TRUSTED_SIGNER_SHA256=$(keytool -exportcert -storetype PKCS12 \
  -keystore "$SPDECODE_RELEASE_STORE_FILE" \
  -storepass:env SPDECODE_RELEASE_STORE_PASSWORD \
  -alias "$SPDECODE_RELEASE_KEY_ALIAS" | sha256sum | awk '{print $1}')
[[ "$SPDECODE_TRUSTED_SIGNER_SHA256" =~ ^[0-9a-f]{64}$ ]] || die "Signing certificate invalid"
BUILDROOT=$(mktemp -d "$ROOT/builds/apk-public.XXXXXX")
SOURCE="$BUILDROOT/source"
clean(){
 git -C "$REPO" worktree remove --force "$SOURCE" >/dev/null 2>&1 || true
 rm -rf "$BUILDROOT"
}
trap clean EXIT
git -C "$REPO" worktree add --detach "$SOURCE" "$SOURCE_SHA" >/dev/null
export ANDROID_HOME="$SDK" ANDROID_SDK_ROOT="$SDK"
export JAVA_HOME="/usr/lib/jvm/java-17-openjdk-amd64"
export GRADLE_OPTS="-Dorg.gradle.jvmargs=-Xmx1536m -Dfile.encoding=UTF-8"
unset SPDECODE_CLOUD_QA_BUILD
unset SPDECODE_OFFLINE_NATIVE SPDECODE_CLOUD_API_BASE_URL SPDECODE_CLOUD_RELEASE
unset SPDECODE_V2_HPKE_PINS SPDECODE_PLAY_APP_SIGNER_SHA256
if [[ "$CHANNEL" == offline ]]; then
 export SPDECODE_OFFLINE_NATIVE=true
 PACKAGE="com.ghostdeveloper.spdecode.offline"
else
 [[ -f "$CFG/api-domain" ]] || die "Dedicated HTTPS API domain missing"
 DOMAIN=$(cat "$CFG/api-domain")
 [[ "$DOMAIN" =~ ^api\.[a-zA-Z0-9.-]+$ ]] || die "Invalid API domain"
 export SPDECODE_CLOUD_API_BASE_URL="https://$DOMAIN"
 export SPDECODE_CLOUD_RELEASE=true
 PACKAGE="com.ghostdeveloper.spdecode"
 if [[ -f "$CFG/keys/v2-hpke-keyring.json" ]];then
  SPDECODE_V2_HPKE_PINS=$(python3 - "$CFG/keys/v2-hpke-keyring.json" <<'PY'
import base64,hashlib,json,pathlib,sys
entries=json.loads(pathlib.Path(sys.argv[1]).read_text())
assert isinstance(entries,list) and 1<=len(entries)<=3
parts=[]
for item in entries:
 value=item['publicKey']
 raw=base64.urlsafe_b64decode(value+'='*((-len(value))%4))
 assert len(raw)==32
 parts.append(hashlib.sha256(raw).digest()[:8].hex()+':'+value)
print(','.join(parts))
PY
)
  export SPDECODE_V2_HPKE_PINS
 fi
 [[ -n "${SPDECODE_V2_HPKE_PINS:-}" ]] || die "No verified HPKE public pins available for Online"
fi
log "Compiling signed $CHANNEL APK (not an AAB) from verified CI source"
(cd "$SOURCE/android" && "$GRADLE" --no-daemon --max-workers=1 :app:assembleRelease)
APK="$SOURCE/android/app/build/outputs/apk/release/app-release.apk"
[[ -s "$APK" ]] || die "Gradle did not produce the release APK"
TOOLS="$SDK/build-tools/35.0.0"
"$TOOLS/apksigner" verify --verbose --print-certs "$APK" > "$BUILDROOT/certificate.txt" ||
  die "APK signature verification failed"
for scheme in v2 v3;do
  grep -Eiq "Verified using $scheme scheme .*: true" "$BUILDROOT/certificate.txt" ||
    die "APK does not have verified $scheme signature"
done
"$TOOLS/apksigner" verify --min-sdk-version 23 --max-sdk-version 23 --verbose "$APK" > "$BUILDROOT/certificate-v1.txt" ||
  die "APK V1 signature verification failed"
grep -Eiq 'Verified using v1 scheme .*: true' "$BUILDROOT/certificate-v1.txt" ||
  die "APK V1 signature is missing"
CERT=$(grep -m1 -i 'Signer #1 certificate SHA-256 digest:' "$BUILDROOT/certificate.txt" | awk '{print $NF}' | tr '[:upper:]' '[:lower:]')
[[ "$CERT" == "$SPDECODE_TRUSTED_SIGNER_SHA256" ]] || die "APK signer does not match persistent key"
"$TOOLS/zipalign" -c -P 16 -v 4 "$APK" >/dev/null || die "Invalid APK alignment"
"$TOOLS/aapt" dump badging "$APK" > "$BUILDROOT/badging.txt"
grep -Fq "package: name='$PACKAGE'" "$BUILDROOT/badging.txt" || die "Unexpected Android application ID"
VERSION=$(sed -n "s/.*versionName='\([^']*\)'.*/\1/p" "$BUILDROOT/badging.txt" | head -1)
CODE=$(sed -n "s/.*versionCode='\([0-9]*\)'.*/\1/p" "$BUILDROOT/badging.txt" | head -1)
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ && "$CODE" =~ ^[1-9][0-9]*$ ]] || die "Invalid release version"
if [[ "$CHANNEL" == offline ]];then
 if "$TOOLS/aapt" dump permissions "$APK" | grep -Fq android.permission.INTERNET;then
  die "Offline APK unexpectedly contains INTERNET permission"
 fi
else
 python3 "$SOURCE/tests/cloud_c5_apk_audit.py" "$APK" ||
   die "Cloud-only APK audit failed"
 python3 "$SOURCE/scripts/android_s3_security_audit.py" --apk "$APK" ||
   die "Public APK security audit failed"
 python3 "$SOURCE/scripts/android_s4_provisioning_audit.py" --apk "$APK" ||
   die "APK provisioning audit failed"
fi
python3 "$PUBLISH" publish "$CHANNEL" --root "$PUBLIC" --apk "$APK" \
 --version "$VERSION" --code "$CODE" --source "$SOURCE_SHA" \
 --signer "$SPDECODE_TRUSTED_SIGNER_SHA256"
log "Public signed $CHANNEL APK published at https://spdecode.xyz/api/downloads/$CHANNEL"
log "Previous verified APK is preserved in the alternate slot for rollback"
