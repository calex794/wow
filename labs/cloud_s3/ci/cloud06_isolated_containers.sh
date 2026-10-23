#!/usr/bin/env bash
# CLOUD-06: independent Docker processes, isolated mounts and S3 credentials.
# ONE physical GitHub runner; metadata copied by the CI host as a fixture.
set -euo pipefail

test "${WOW_MINIO_ENDPOINT:?}" = "http://127.0.0.1:9000"
: "${WOW_MINIO_BUCKET:?}"
: "${WOW_ALICE_ACCESS:?}"
: "${WOW_ALICE_SECRET:?}"
: "${WOW_BOB_ACCESS:?}"
: "${WOW_BOB_SECRET:?}"

repo_root="$(pwd)"
binary="$repo_root/labs/cloud_s3/target/debug/cloud06_node"
test -x "$binary"
# AWS SDK rustls native-roots must see a valid trust bundle. Minimal Ubuntu
# runner images omit certificates; mount the host's read-only verified bundle.
cert_bundle="/etc/ssl/certs/ca-certificates.crt"
test -s "$cert_bundle"
base="$RUNNER_TEMP/wow-cloud06-container"
alice="$base/alice"
bob="$base/bob"
mkdir -m 700 -p "$alice" "$bob"
printf '%s' "opaque pre-encrypted W3 fixture, no plaintext or signed W4" > "$alice/out.w3"
printf '%s' "opaque encrypted W4 fixture" > "$bob/out.w4"
"$binary" HASH unused "$alice/out.w3" "$alice/w3.digest"
"$binary" HASH unused "$bob/out.w4" "$bob/w4.digest"

net="wow-cloud06-private"
docker network create --internal "$net" >/dev/null
cleanup() {
  docker network disconnect "$net" wow-cloud02-minio >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
}
trap cleanup EXIT
docker network connect "$net" wow-cloud02-minio

# Neither worker receives the MinIO administrator's credentials or the peer mount.
run_alice() {
  docker run --rm --network "$net" --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 --memory 256m \
    --user "$(id -u):$(id -g)" \
    -v "$binary:/opt/cloud06_node:ro" \
    -v "$cert_bundle:/etc/ssl/certs/ca-certificates.crt:ro" \
    -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    -v "$alice:/state:rw" \
    -e WOW_MINIO_ENDPOINT="http://wow-cloud02-minio:9000" \
    -e WOW_MINIO_BUCKET="$WOW_MINIO_BUCKET" \
    -e WOW_ALICE_ACCESS="$WOW_ALICE_ACCESS" \
    -e WOW_ALICE_SECRET="$WOW_ALICE_SECRET" \
    -e WOW_EXPECTED_BLAKE3="${WOW_EXPECTED_BLAKE3-}" \
    ubuntu:24.04 /opt/cloud06_node ALICE "$@"
}
run_bob() {
  docker run --rm --network "$net" --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 --memory 256m \
    --user "$(id -u):$(id -g)" \
    -v "$binary:/opt/cloud06_node:ro" \
    -v "$cert_bundle:/etc/ssl/certs/ca-certificates.crt:ro" \
    -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    -v "$bob:/state:rw" \
    -e WOW_MINIO_ENDPOINT="http://wow-cloud02-minio:9000" \
    -e WOW_MINIO_BUCKET="$WOW_MINIO_BUCKET" \
    -e WOW_BOB_ACCESS="$WOW_BOB_ACCESS" \
    -e WOW_BOB_SECRET="$WOW_BOB_SECRET" \
    -e WOW_EXPECTED_BLAKE3="${WOW_EXPECTED_BLAKE3-}" \
    ubuntu:24.04 /opt/cloud06_node BOB "$@"
}

# No shared filesystem is mounted in both actor containers. Only the
# workflow runner can read both as a trusted test orchestrator.
run_alice put /state/out.w3 /state/w3.version
cp "$alice/w3.version" "$bob/w3.version"
cp "$alice/w3.digest" "$bob/w3.digest"
export WOW_EXPECTED_BLAKE3="$(cat "$bob/w3.digest")"
run_bob read /state/w3.version /state/received.w3
cmp "$alice/out.w3" "$bob/received.w3"

unset WOW_EXPECTED_BLAKE3
run_bob put /state/out.w4 /state/w4.version
cp "$bob/w4.version" "$alice/w4.version"
cp "$bob/w4.digest" "$alice/w4.digest"
export WOW_EXPECTED_BLAKE3="$(cat "$alice/w4.digest")"
run_alice read /state/w4.version /state/received.w4
cmp "$bob/out.w4" "$alice/received.w4"
unset WOW_EXPECTED_BLAKE3

# A write-only participant cannot reconcile its own upload without a
# separately issued readback capability; this must fail closed.
run_alice reconcile /state/out.w3 /state/reconcile.status
grep -Fx 'RECONCILIATION_NEEDS_READ_CAPABILITY' "$alice/reconcile.status" >/dev/null
echo "CLOUD-06: isolated-container W3/W4 transport and IAM checks PASS"
