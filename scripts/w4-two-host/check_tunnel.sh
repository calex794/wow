#!/bin/sh
# Network-free negative and argument tests for the two-host SSH launcher.
set -eu
here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
cat > "$tmp/ssh" <<'MOCK'
#!/bin/sh
case "$*" in
    *'printf "%s" "$HOME"'*) printf '/home/tester'; exit 0;;
    *'umask 077; mkdir -p'* ) exit 0;;
    *) printf '%s\n' "$@" > "$WOW_MOCK_LOG"; exit 0;;
esac
MOCK
chmod 700 "$tmp/ssh"
export PATH="$tmp:$PATH" WOW_MOCK_LOG="$tmp/log"
export WOW_E2E_SESSION="test_run_7"
sh "$here/ssh_tunnel.sh" receiver receiver@relay.example > "$tmp/out"
grep -qx -- "-R" "$tmp/log"
grep -qx -- "/home/tester/.ssh/wow-e2e/test_run_7.sock:127.0.0.1:42042" "$tmp/log"
grep -qx -- "StrictHostKeyChecking=yes" "$tmp/log"
grep -qx -- "ExitOnForwardFailure=yes" "$tmp/log"
! grep -q -- "0.0.0.0" "$tmp/log"
sh "$here/ssh_tunnel.sh" sender sender@relay.example > "$tmp/out"
grep -qx -- "-L" "$tmp/log"
grep -qx -- "127.0.0.1:42043:/home/tester/.ssh/wow-e2e/test_run_7.sock" "$tmp/log"
! grep -q -- "0.0.0.0" "$tmp/log"
if WOW_E2E_SESSION="invalid/session" sh "$here/ssh_tunnel.sh" sender a@b > /dev/null 2>&1; then
    echo "bad session accepted" >&2
    exit 1
fi
if sh "$here/ssh_tunnel.sh" receiver '-oProxyCommand=evil' > /dev/null 2>&1; then
    echo "option injection accepted" >&2
    exit 1
fi
echo "W4_SSH_TUNNEL_PREFLIGHT_PASS"
