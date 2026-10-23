#!/bin/sh
# One-way SSH forwarding for the WOW W4 two-host laboratory.
# Run using: sh ssh_tunnel.sh receiver|sender user@vps
# The relay uses a UNIX socket in a private SSH-owned directory on VPS;
# no public relay TCP port is created. SSH host keys MUST be pre-pinned.
set -eu
if [ "$#" -ne 2 ]; then
    echo "usage: sh ssh_tunnel.sh receiver|sender user@vps" >&2
    exit 2
fi
role=$1
host=$2
case "$role" in receiver|sender) ;; *) echo "invalid role" >&2; exit 2;; esac
case "$host" in
    ""|-*|*@*/*|*[!A-Za-z0-9_@.:-]*)
        echo "invalid SSH destination" >&2
        exit 2
        ;;
esac
command -v ssh >/dev/null 2>&1 || { echo "OpenSSH is required" >&2; exit 2; }

# Reuse exactly the same ASCII session label on both physical machines.
session=${WOW_E2E_SESSION:-w4-labo}
case "$session" in
    ""|*[!A-Za-z0-9_-]*)
        echo "WOW_E2E_SESSION must be an ASCII alphanumeric label" >&2
        exit 2
        ;;
esac
if [ "${#session}" -gt 24 ]; then
    echo "WOW_E2E_SESSION too long" >&2
    exit 2
fi
# StrictHostKeyChecking=yes fails when the trusted VPS host key has not
# been enrolled in known_hosts. Never auto-accept or disable host pinning.
remote_home=$(ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o ConnectTimeout=10 "$host" 'printf "%s" "$HOME"')
case "$remote_home" in
    /*) ;;
    *) echo "invalid remote HOME" >&2; exit 2;;
esac
case "$remote_home" in
    *[!A-Za-z0-9_./-]*|*..*)
        echo "unsafe remote HOME characters" >&2
        exit 2
        ;;
esac
# The daemon must support AllowStreamLocalForwarding. For a separate
# privilege boundary, create a dedicated VPS user for this experiment.
ssh -T -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o ConnectTimeout=10 "$host" \
    'umask 077; mkdir -p "$HOME/.ssh/wow-e2e"; chmod 700 "$HOME/.ssh/wow-e2e"'
remote_socket="$remote_home/.ssh/wow-e2e/$session.sock"
echo "Protected remote Unix socket: $remote_socket"
echo "Keep this terminal open only while running the lab. Ctrl-C stops it."
if [ "$role" = receiver ]; then
    # A local listener on the recipient PC is connected to this SSH socket.
    exec ssh -T -N \
        -o BatchMode=yes -o StrictHostKeyChecking=yes \
        -o ExitOnForwardFailure=yes \
        -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
        -R "$remote_socket:127.0.0.1:42042" "$host"
fi
exec ssh -T -N \
    -o BatchMode=yes -o StrictHostKeyChecking=yes \
    -o ExitOnForwardFailure=yes \
    -o ServerAliveInterval=15 -o ServerAliveCountMax=3 \
    -L "127.0.0.1:42043:$remote_socket" "$host"
