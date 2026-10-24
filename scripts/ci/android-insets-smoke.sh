#!/usr/bin/env bash
# Run by reactivecircus in a single shell invocation: its action does not
# interpret multi-line 'script' as one compound shell statement.
set -Eeuo pipefail
adb logcat -c || true
if (cd android && gradle --no-daemon :app:connectedDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=com.ghostdeveloper.spdecode.PlayEdgeToEdgeInstrumentedTest); then
  exit 0
fi
echo "::error::Android instrumentation failed; emulator diagnostics follow"
adb logcat -d -v time -t 650 \
  | grep -E 'AndroidRuntime|FATAL EXCEPTION|Instrumentation|com.ghostdeveloper.spdecode|Process crashed' \
  | tail -n 140 || true
exit 1
