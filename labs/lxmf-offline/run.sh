#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
ROOT="$(mktemp -d)"
cleanup() {
 rc=$?
 for f in "$ROOT"/*.log; do
  if test -f "$f"; then echo "=== $(basename "$f") ==="; tail -n 45 "$f"; fi
 done
 for n in a p b; do
  sudo ip netns pids "lx-$n" 2>/dev/null | xargs -r sudo kill || true
  sudo ip netns del "lx-$n" 2>/dev/null || true
 done
 exit "$rc"
}
trap cleanup EXIT
for n in a p b; do sudo ip netns add "lx-$n"; sudo ip -n "lx-$n" link set lo up; mkdir -p "$ROOT/$n"; done
sudo ip link add lx-a type veth peer name lx-pa
sudo ip link add lx-b type veth peer name lx-pb
sudo ip link set lx-a netns lx-a
sudo ip link set lx-pa netns lx-p
sudo ip link set lx-b netns lx-b
sudo ip link set lx-pb netns lx-p
sudo ip -n lx-a addr add 10.92.1.1/30 dev lx-a
sudo ip -n lx-p addr add 10.92.1.2/30 dev lx-pa
sudo ip -n lx-b addr add 10.92.2.1/30 dev lx-b
sudo ip -n lx-p addr add 10.92.2.2/30 dev lx-pb
for x in 'a lx-a' 'p lx-pa' 'p lx-pb' 'b lx-b'; do
 read -r n nic <<< "$x"
 sudo ip -n "lx-$n" link set "$nic" up
done
if sudo ip netns exec lx-a ping -c1 -W1 10.92.2.1 >/dev/null 2>&1; then echo 'FAIL direct A-B'; exit 1; fi
echo LXMF_UNDERLAY_A_B_BLOCKED
cat > "$ROOT/a/config" <<'EOF'
[reticulum]
enable_transport = No
share_instance = No
[interfaces]
  [[to-propagation]]
  type = TCPClientInterface
  enabled = yes
  target_host = 10.92.1.2
  target_port = 4242
EOF
cat > "$ROOT/p/config" <<'EOF'
[reticulum]
enable_transport = Yes
share_instance = No
[interfaces]
  [[from-a]]
  type = TCPServerInterface
  enabled = yes
  listen_ip = 10.92.1.2
  listen_port = 4242
  [[from-b]]
  type = TCPServerInterface
  enabled = yes
  listen_ip = 10.92.2.2
  listen_port = 4242
EOF
cat > "$ROOT/b/config" <<'EOF'
[reticulum]
enable_transport = No
share_instance = No
[interfaces]
  [[to-propagation]]
  type = TCPClientInterface
  enabled = yes
  target_host = 10.92.2.2
  target_port = 4242
EOF
PYTHON="${GITHUB_WORKSPACE:?}/.venv/bin/python"
PROBE="$(pwd)/lxmf_probe.py"
sudo ip netns exec lx-p "$PYTHON" "$PROBE" node --config "$ROOT/p" --storage "$ROOT/p" > "$ROOT/node.log" 2>&1 &
for i in $(seq 1 30); do test -s "$ROOT/p/node.addr" && break; sleep 1; done
test -s "$ROOT/p/node.addr"
sudo ip netns exec lx-b "$PYTHON" "$PROBE" advertise --config "$ROOT/b" --storage "$ROOT/b" > "$ROOT/advertise.log" 2>&1 &
for i in $(seq 1 35); do test -s "$ROOT/b/recipient.addr" && break; sleep 1; done
test -s "$ROOT/b/recipient.addr"
sudo ip netns exec lx-a "$PYTHON" "$PROBE" sender --config "$ROOT/a" --storage "$ROOT/a" --node-addr "$ROOT/p/node.addr" --recipient-addr "$ROOT/b/recipient.addr" --recipient-offline "$ROOT/b/offline" --sender-ready "$ROOT/a/ready" --delivered "$ROOT/b/delivered" > "$ROOT/sender.log" 2>&1 &
for i in $(seq 1 90); do test -s "$ROOT/a/ready" && break; sleep 1; done
test -s "$ROOT/a/ready"
sudo ip netns pids lx-b | xargs -r sudo kill
sleep 3
test -z "$(sudo ip netns pids lx-b)"
printf "recipient is offline\n" > "$ROOT/b/offline"
echo LXMF_RECIPIENT_STOPPED_BEFORE_SEND
for i in $(seq 1 100); do test -s "$ROOT/p/stored" && break; sleep 1; done
test -s "$ROOT/p/stored"
echo LXMF_CIPHERTEXT_STORED_WHILE_B_OFFLINE
sudo ip netns exec lx-b "$PYTHON" "$PROBE" sync --config "$ROOT/b" --storage "$ROOT/b" --node-addr "$ROOT/p/node.addr" --recipient-addr "$ROOT/b/recipient.addr" --delivered "$ROOT/b/delivered" > "$ROOT/sync.log" 2>&1 &
for i in $(seq 1 105); do grep -q LXMF_SECOND_SYNC_NO_DUPLICATE_PASS "$ROOT/sync.log" && break; sleep 1; done
grep -q LXMF_SECOND_SYNC_NO_DUPLICATE_PASS "$ROOT/sync.log"
grep -q LXMF_OFFLINE_RECIPIENT_RECEIVED_VALIDATED "$ROOT/sync.log"
echo LXMF_OFFLINE_STORE_FORWARD_PASS
