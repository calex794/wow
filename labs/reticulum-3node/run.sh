#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
ROOT="$(mktemp -d)"
cleanup() {
  rc=$?
  for f in "$ROOT"/*.log; do
    if test -f "$f"; then echo "=== $(basename "$f") ==="; tail -n 60 "$f"; fi
  done
  for n in a t b; do
    sudo ip netns pids "rns-$n" 2>/dev/null | xargs -r sudo kill || true
    sudo ip netns del "rns-$n" 2>/dev/null || true
  done
  exit "$rc"
}
trap cleanup EXIT
for n in a t b; do sudo ip netns add "rns-$n"; sudo ip -n "rns-$n" link set lo up; done
sudo ip link add rn-a type veth peer name rn-ta
sudo ip link add rn-b type veth peer name rn-tb
sudo ip link set rn-a netns rns-a
sudo ip link set rn-ta netns rns-t
sudo ip link set rn-b netns rns-b
sudo ip link set rn-tb netns rns-t
sudo ip -n rns-a addr add 10.91.1.1/30 dev rn-a
sudo ip -n rns-t addr add 10.91.1.2/30 dev rn-ta
sudo ip -n rns-b addr add 10.91.2.1/30 dev rn-b
sudo ip -n rns-t addr add 10.91.2.2/30 dev rn-tb
for v in 'a rn-a' 't rn-ta' 'b rn-b' 't rn-tb'; do
  read -r n nic <<< "$v"
  sudo ip -n "rns-$n" link set "$nic" up
done
if sudo ip netns exec rns-a ping -c1 -W1 10.91.2.1 >/dev/null 2>&1; then
  echo 'FAIL A can reach B without transport'; exit 1
fi
echo UNDERLAY_A_B_BLOCKED
for n in a t b; do mkdir -p "$ROOT/$n"; done
cat > "$ROOT/a/config" <<'EOF'
[reticulum]
enable_transport = No
share_instance = No
[interfaces]
  [[to-t]]
  type = TCPClientInterface
  enabled = yes
  target_host = 10.91.1.2
  target_port = 4242
EOF
cat > "$ROOT/t/config" <<'EOF'
[reticulum]
enable_transport = Yes
share_instance = No
[interfaces]
  [[a-listen]]
  type = TCPServerInterface
  enabled = yes
  listen_ip = 10.91.1.2
  listen_port = 4242
  [[b-listen]]
  type = TCPServerInterface
  enabled = yes
  listen_ip = 10.91.2.2
  listen_port = 4242
EOF
cat > "$ROOT/b/config" <<'EOF'
[reticulum]
enable_transport = No
share_instance = No
[interfaces]
  [[to-t]]
  type = TCPClientInterface
  enabled = yes
  target_host = 10.91.2.2
  target_port = 4242
EOF
PROBE="$(pwd)/rns_probe.py"
PYTHON="${GITHUB_WORKSPACE:?}/.venv/bin/python"
sudo ip netns exec rns-t "$PYTHON" "$PROBE" transport --config "$ROOT/t" > "$ROOT/transport.log" 2>&1 &
sleep 4
sudo ip netns exec rns-b "$PYTHON" "$PROBE" receive --config "$ROOT/b" --address "$ROOT/receiver.addr" --done "$ROOT/receiver.done" > "$ROOT/receiver.log" 2>&1 &
for i in $(seq 1 20); do
  test -s "$ROOT/receiver.addr" && break
  sleep 1
done
test -s "$ROOT/receiver.addr"
sudo ip netns exec rns-a "$PYTHON" "$PROBE" send --config "$ROOT/a" --address "$ROOT/receiver.addr" > "$ROOT/sender.log" 2>&1
test -f "$ROOT/receiver.done"
grep -q RNS_TRANSPORT_PROOF_PASS "$ROOT/sender.log"
grep -q RNS_RECEIVER_PAYLOAD_OK "$ROOT/receiver.log"
echo RNS_THREE_NODE_TRANSPORT_PASS
