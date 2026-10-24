#!/usr/bin/env bash
set -euo pipefail
test "$WOW_MINIO_ENDPOINT" = "http://127.0.0.1:9000"
base="$RUNNER_TEMP/wow-cloud07"
a="$base/alice"; b="$base/bob"
mkdir -m 700 -p "$a" "$b"
binary="$(pwd)/labs/cloud_s3/target/debug/cloud07_actor"
test -x "$binary"
net="wow-cloud07"
docker network create --internal "$net" >/dev/null
trap 'docker network disconnect "$net" wow-cloud02-minio >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null 2>&1 || true' EXIT
docker network connect "$net" wow-cloud02-minio
actor(){
  local who="$1" op="$2" dir access secret
  if [ "$who" = alice ]; then
    dir="$a"; access="$WOW_ALICE_ACCESS"; secret="$WOW_ALICE_SECRET"
  else
    dir="$b"; access="$WOW_BOB_ACCESS"; secret="$WOW_BOB_SECRET"
  fi
  docker run --rm --network "$net" --read-only --cap-drop ALL \
    --security-opt no-new-privileges --pids-limit 64 --memory 512m \
    --user "$(id -u):$(id -g)" -v "$binary:/opt/actor:ro" \
    -v "$dir:/state:rw" \
    -v /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro \
    -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    -e WOW_MINIO_ENDPOINT=http://wow-cloud02-minio:9000 \
    -e WOW_MINIO_BUCKET="$WOW_MINIO_BUCKET" \
    -e WOW_SELF_ACCESS="$access" -e WOW_SELF_SECRET="$secret" \
    ubuntu:24.04 /opt/actor "$who" "$op"
}
actor alice init
actor bob init
cp "$a/public.sign" "$b/peer.sign"
cp "$b/public.sign" "$a/peer.sign"
cp "$a/public.hpke" "$b/peer.hpke"
cp "$b/public.hpke" "$a/peer.hpke"
actor alice send
cp "$a/forward.meta" "$b/forward.meta"
# Actual process is killed BEFORE SQLite commit: no W4 survives.
docker run -d --name wow-cloud07-pre --network "$net" --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" -v "$binary:/opt/actor:ro" \
  -v "$b:/state:rw" \
  -v /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro \
  -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
  -e WOW_MINIO_ENDPOINT=http://wow-cloud02-minio:9000 \
  -e WOW_MINIO_BUCKET="$WOW_MINIO_BUCKET" \
  -e WOW_SELF_ACCESS="$WOW_BOB_ACCESS" -e WOW_SELF_SECRET="$WOW_BOB_SECRET" \
  ubuntu:24.04 /opt/actor bob precommit-pause >/dev/null
for _ in $(seq 1 100); do
  if test -f "$b/verified_precommit.marker"; then break; fi
  sleep 0.1
done
test -f "$b/verified_precommit.marker"
docker kill wow-cloud07-pre >/dev/null
docker rm wow-cloud07-pre >/dev/null
actor bob check-none
# Commit and SIGKILL process after durable SQLite W4 transaction.
docker run -d --name wow-cloud07-post --network "$net" --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" -v "$binary:/opt/actor:ro" \
  -v "$b:/state:rw" \
  -v /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro \
  -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
  -e WOW_MINIO_ENDPOINT=http://wow-cloud02-minio:9000 \
  -e WOW_MINIO_BUCKET="$WOW_MINIO_BUCKET" \
  -e WOW_SELF_ACCESS="$WOW_BOB_ACCESS" -e WOW_SELF_SECRET="$WOW_BOB_SECRET" \
  ubuntu:24.04 /opt/actor bob commit-pause >/dev/null
for _ in $(seq 1 100); do
  if test -f "$b/committed.marker"; then break; fi
  sleep 0.1
done
test -f "$b/committed.marker"
docker kill wow-cloud07-post >/dev/null
docker rm wow-cloud07-post >/dev/null
# Crash happened after Bob's atomic W4 commit. Stop the storage endpoint,
# then check local receipt durability without touching the network.
docker pause wow-cloud02-minio >/dev/null
actor bob offline-receipt
actor alice verify-pending
# Confirm that network loss did not accidentally produce a remote receipt.
test ! -e "$b/return.meta"
docker unpause wow-cloud02-minio >/dev/null
# The endpoint must be responsive before replay; readiness is not publication.
for _ in $(seq 1 100); do
  if curl --fail --silent --max-time 2 http://127.0.0.1:9000/minio/health/live >/dev/null; then break; fi
  sleep 0.1
done
curl --fail --silent --max-time 2 http://127.0.0.1:9000/minio/health/live >/dev/null
actor bob verify-duplicate
# The return ciphertext is persisted and fsynced before cloud publication.
# Kill Bob after preparing it, then ensure the identical bytes survive.
docker run -d --name wow-cloud07-prepared --network "$net" --read-only \
  --cap-drop ALL --security-opt no-new-privileges \
  --user "$(id -u):$(id -g)" -v "$binary:/opt/actor:ro" \
  -v "$b:/state:rw" \
  -v /etc/ssl/certs/ca-certificates.crt:/etc/ssl/certs/ca-certificates.crt:ro \
  -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
  -e WOW_MINIO_ENDPOINT=http://wow-cloud02-minio:9000 \
  -e WOW_MINIO_BUCKET="$WOW_MINIO_BUCKET" \
  -e WOW_SELF_ACCESS="$WOW_BOB_ACCESS" -e WOW_SELF_SECRET="$WOW_BOB_SECRET" \
  ubuntu:24.04 /opt/actor bob prepare-pause >/dev/null
for _ in $(seq 1 100); do
  if test -f "$b/envelope_prepared.marker"; then break; fi
  sleep 0.1
done
test -f "$b/envelope_prepared.marker"
docker kill wow-cloud07-prepared >/dev/null
docker rm wow-cloud07-prepared >/dev/null
actor bob prepare-check
cp "$b/return.envelope" "$RUNNER_TEMP/cloud07_saved_w4"
# Network fault proxy sees real 2xx PUT from MinIO but drops Bob's ACK.
# It is reachable solely on this CI-created internal Docker network.
docker run -d --rm --name wow-cloud07-proxy --network "$net" \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  -v "$(pwd)/labs/cloud_s3/ci/lost_put_ack_proxy.py:/opt/fault.py:ro" \
  -e WOW_PROXY_DOCKER_LAB=1 python:3.12-slim python /opt/fault.py >/dev/null
for _ in $(seq 1 80); do
  if docker exec wow-cloud07-proxy python -c 'import socket; socket.create_connection(("127.0.0.1",9001),1).close()' >/dev/null 2>&1; then break; fi
  sleep 0.1
done
actor bob lost-ack
docker stop wow-cloud07-proxy >/dev/null
# Metadata is NOT forged from an upload response. Alice can only read Bob's
# return prefix; the test conductor passes opaque bytes, not credentials.
cp "$b/return.envelope" "$a/return.envelope"
actor alice reconcile-return
cp "$a/return.meta" "$b/return.meta"
actor bob accept-pin
cmp "$b/return.envelope" "$RUNNER_TEMP/cloud07_saved_w4"
actor alice reject-corrupt
actor alice confirm
actor alice assert-final
actor alice confirm
echo "CLOUD-07: MinIO outage, journal-first W4, SIGKILL and replay PASS"
