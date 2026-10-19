#!/usr/bin/env bash
set -euo pipefail

# Invoked as ONE command by reactivecircus/android-emulator-runner.
# That action executes each YAML script line in a separate /bin/sh process,
# so cross-line local variables are unsafe there.
adb wait-for-device

root="$(git rev-parse --show-toplevel)"
target="$root/noq/target/x86_64-linux-android/debug/deps"
binary="$(find "$target" -maxdepth 1 -type f -name 'noq_proto-*' -perm /111 -print -quit)"
test -n "$binary"

adb push "$binary" /data/local/tmp/noq_proto_gate
adb shell chmod 755 /data/local/tmp/noq_proto_gate

for test_name in \
  tests::multipath::backup_path_keepalive_not_suppressed_by_incoming_ping \
  tests::multipath::regression_locally_abandoned_unseen_path_discarded \
  connection::streams::state::tests::stopped_reset_flow_control \
  connection::streams::state::tests::reset_stopped_flow_control; do
  echo "ANDROID EMULATOR RUN: $test_name"
  adb shell "/data/local/tmp/noq_proto_gate $test_name --exact --nocapture" \
    | tee /tmp/noq-android-case.log
  grep -q 'test result: ok. 1 passed; 0 failed' /tmp/noq-android-case.log
done

adb shell rm -f /data/local/tmp/noq_proto_gate
echo "Android emulator: four exact combined noq regression tests passed."
