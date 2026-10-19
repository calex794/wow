#!/usr/bin/env bash
set -Eeuo pipefail
cd "$(dirname "$0")"
LAB_ROOT="$(mktemp -d)"
function cleanup() {
  rc=$?
  echo "DIAGNOSTICS status=$rc"
  for f in "$LAB_ROOT"/*.log; do
    test ! -f "$f" || { echo "== $(basename "$f") =="; tail -n 65 "$f"; }
  done
  for n in a b c; do
    sudo ip netns exec "ak-$n" ip -6 -o addr show dev ygg0 2>/dev/null || true
    sudo ip netns pids "ak-$n" 2>/dev/null | xargs -r sudo kill || true
  done
  for n in a b c; do sudo ip netns del "ak-$n" 2>/dev/null || true; done
  exit "$rc"
}
trap cleanup EXIT
: "${YGG_RELEASE:?}"
: "${YGG_SHA256:?}"
curl -fLsS --retry 3 "$YGG_RELEASE" -o "$LAB_ROOT/ygg.deb"
echo "$YGG_SHA256  $LAB_ROOT/ygg.deb" | sha256sum -c -
mkdir "$LAB_ROOT/pkg"
dpkg-deb -x "$LAB_ROOT/ygg.deb" "$LAB_ROOT/pkg"
YGG="$(find "$LAB_ROOT/pkg" -type f -name yggdrasil | head -n 1)"
test -x "$YGG"
"$YGG" -version

for n in a b c; do sudo ip netns add "ak-$n"; sudo ip -n "ak-$n" link set lo up; done
sudo ip link add ak-a0 type veth peer name ak-b0
sudo ip link add ak-c0 type veth peer name ak-b1
sudo ip link set ak-a0 netns ak-a
sudo ip link set ak-b0 netns ak-b
sudo ip link set ak-c0 netns ak-c
sudo ip link set ak-b1 netns ak-b
sudo ip -n ak-a addr add 10.201.1.1/30 dev ak-a0
sudo ip -n ak-b addr add 10.201.1.2/30 dev ak-b0
sudo ip -n ak-b addr add 10.201.2.1/30 dev ak-b1
sudo ip -n ak-c addr add 10.201.2.2/30 dev ak-c0
for spec in 'a ak-a0' 'b ak-b0' 'b ak-b1' 'c ak-c0'; do
  read -r n nic <<< "$spec"
  sudo ip -n "ak-$n" link set "$nic" up
done
if sudo ip netns exec ak-a ping -c1 -W1 10.201.2.2 >/dev/null 2>&1; then
  echo 'FAIL underlay not isolated'; exit 1
fi
echo 'UNDERLAY_ISOLATION_OK'
for n in a b c; do "$YGG" -genconf -json > "$LAB_ROOT/$n.raw.json"; done
for n in a b c; do
  case "$n" in
    a) peers='["tls://10.201.1.2:4466"]'; listener='[]';;
    b) peers='[]'; listener='["tls://0.0.0.0:4466"]';;
    c) peers='["tls://10.201.2.1:4466"]'; listener='[]';;
  esac
  jq --argjson peers "$peers" --argjson listener "$listener"     '.Peers=$peers | .Listen=$listener | .AdminListen="none" | .MulticastInterfaces=[] | .IfName="ygg0"'     "$LAB_ROOT/$n.raw.json" > "$LAB_ROOT/$n.json"
  sudo ip netns exec "ak-$n" "$YGG" -useconffile "$LAB_ROOT/$n.json" > "$LAB_ROOT/ygg-$n.log" 2>&1 &
done
function ygg_addr() {
  sudo ip netns exec "ak-$1" ip -j -6 addr show dev ygg0 2>/dev/null |
    jq -r '.[0].addr_info[] | select(.scope=="global") | .local' | head -n 1
}
addr_a=''; addr_c=''
for i in $(seq 1 80); do
  addr_a="$(ygg_addr a || true)"
  addr_c="$(ygg_addr c || true)"
  if [[ -n "$addr_a" && -n "$addr_c" ]] &&
      sudo ip netns exec ak-a ping -6 -c1 -W1 "$addr_c" >/dev/null 2>&1; then
    echo "YGG_MULTIHOP_IP_OK from=$addr_a to=$addr_c hop=b"; break
  fi
  sleep 1
done
if [[ -z "$addr_a" || -z "$addr_c" ]] ||
    ! sudo ip netns exec ak-a ping -6 -c1 -W2 "$addr_c"; then
  echo 'FAIL no multihop IPv6'; exit 1
fi
PROBE="${GITHUB_WORKSPACE:?}/roha/target/release/examples/mesh_probe"
sudo ip netns exec ak-c "$PROBE" server "$addr_c" 51001 > "$LAB_ROOT/roha-server.log" 2>&1 &
sleep 3
sudo ip netns exec ak-a "$PROBE" client "$addr_a" "$addr_c" 51001 |
  tee "$LAB_ROOT/roha-client.log"
for i in $(seq 1 12); do
  grep -q SERVER_ECHO_OK "$LAB_ROOT/roha-server.log" && break
  sleep 1
done
grep -q CLIENT_ROHA_QUIC_OK "$LAB_ROOT/roha-client.log"
grep -q SERVER_ECHO_OK "$LAB_ROOT/roha-server.log"
echo 'STAYA_YGG_ROHA_3NODE_PASS no application relay'
