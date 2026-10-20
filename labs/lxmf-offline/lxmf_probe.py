#!/usr/bin/env python3
"""Real LXMF offline propagation-node experiment, isolated from Akula files.

Roles use private RNS configs. A and B never share their private identities.
All markers are laboratory-only and do not claim Akula File Gate durability.
"""
import argparse
import os
import sys
import time
from pathlib import Path

import LXMF
import RNS

MARKER = "AKULA_LXMF_OFFLINE_RECEIPT_01"
SLEEP = 0.5


def emit(*parts):
    print(*parts, flush=True)


def wait_for(path, seconds=95):
    deadline = time.monotonic() + seconds
    path = Path(path)
    while time.monotonic() < deadline:
        if path.is_file() and path.stat().st_size:
            return path.read_text().strip()
        time.sleep(SLEEP)
    raise TimeoutError("marker missing: " + path.name)


def read_hash(path):
    return bytes.fromhex(wait_for(path))


def wait_path(destination, timeout=95, announce=None):
    end = time.monotonic() + timeout
    next_request = 0
    while time.monotonic() < end:
        if RNS.Transport.has_path(destination) and RNS.Identity.recall(destination):
            return
        if time.monotonic() > next_request:
            RNS.Transport.request_path(destination)
            if announce:
                announce()
            next_request = time.monotonic() + 4.0
        time.sleep(SLEEP)
    raise TimeoutError("no verified RNS announce/path for " + destination.hex())


def identity_file(path):
    path = Path(path)
    if path.is_file():
        ident = RNS.Identity.from_file(str(path))
        assert ident is not None
        return ident
    ident = RNS.Identity()
    assert ident.to_file(str(path))
    os.chmod(path, 0o600)
    return ident


def begin(args):
    RNS.Reticulum(args.config)
    storage = Path(args.storage)
    storage.mkdir(parents=True, exist_ok=True)
    return storage


def node(args):
    storage = begin(args)
    identity = identity_file(storage / "node-identity")
    router = LXMF.LXMRouter(identity=identity, storagepath=str(storage),
                            name="akula-lxmf-lab", autopeer=False, propagation_cost=13)
    router.set_message_storage_limit(megabytes=4)
    router.enable_propagation()
    if args.expect_recovered:
        assert len(router.propagation_entries) == args.expect_recovered, (
            "reloaded message count mismatch: " + str(len(router.propagation_entries))
        )
        for entry in router.propagation_entries.values():
            blob = Path(entry[1]).read_bytes()
            assert blob and MARKER.encode() not in blob
        emit("LXMF_RESTART_INDEX_RECOVERED count=" + str(len(router.propagation_entries)))
    (storage / "node.addr").write_text(router.propagation_destination.hash.hex())
    emit("LXMF_PROPAGATION_NODE_READY", router.propagation_destination.hash.hex())
    next_announce = 0
    notified = False
    while True:
        if time.monotonic() >= next_announce:
            router.propagation_destination.announce(
                app_data=router.get_propagation_node_app_data()
            )
            next_announce = time.monotonic() + 7
        if router.propagation_entries and not notified:
            for entry in router.propagation_entries.values():
                blob = Path(entry[1]).read_bytes()
                assert MARKER.encode() not in blob, "plaintext visible in propagation storage"
                assert len(blob) > 64
            (storage / "stored").write_text(str(len(router.propagation_entries)))
            emit("LXMF_OFFLINE_CIPHERTEXT_STORED count=" + str(len(router.propagation_entries)))
            notified = True
        time.sleep(SLEEP)


def advertise(args):
    storage = begin(args)
    identity = identity_file(storage / "b-identity")
    router = LXMF.LXMRouter(storagepath=str(storage))
    dest = router.register_delivery_identity(identity, display_name="lab-recipient")
    (storage / "recipient.addr").write_text(dest.hash.hex())
    emit("LXMF_RECIPIENT_PREANNOUNCE", dest.hash.hex())
    deadline = time.monotonic() + 95
    while time.monotonic() < deadline:
        router.announce(dest.hash)
        time.sleep(2.0)
    raise TimeoutError("recipient was not switched offline")


def sender(args):
    storage = begin(args)
    router = LXMF.LXMRouter(storagepath=str(storage))
    src = router.register_delivery_identity(RNS.Identity(), display_name="lab-sender")
    # Lab pairing: export only the public key and its derived LXMF destination.
    # This simulates a user-verified device identity, never a secret key.
    Path(args.sender_public).write_text(
        src.hash.hex() + " " + src.identity.get_public_key().hex() + "\n"
    )
    emit("LXMF_SENDER_PUBLIC_IDENTITY_PINNED")
    next_announce = 0

    def announce():
        nonlocal next_announce
        if time.monotonic() >= next_announce:
            router.announce(src.hash)
            next_announce = time.monotonic() + 4

    node_dest = read_hash(args.node_addr)
    recipient_hash = read_hash(args.recipient_addr)
    wait_path(node_dest, announce=announce)
    wait_path(recipient_hash, announce=announce)
    assert RNS.Transport.hops_to(recipient_hash) >= 2
    Path(args.sender_ready).write_text("recipient and node paths learned")
    emit("LXMF_SENDER_LEARNED_RECIPIENT_AND_NODE")

    wait_for(args.recipient_offline, seconds=95)
    dest_identity = RNS.Identity.recall(recipient_hash)
    assert dest_identity is not None, "sender has no recipient public identity"
    destination = RNS.Destination(dest_identity, RNS.Destination.OUT,
                                  RNS.Destination.SINGLE, "lxmf", "delivery")
    assert destination.hash == recipient_hash
    router.set_outbound_propagation_node(node_dest)
    msg = LXMF.LXMessage(destination, src, MARKER, "offline-lab",
                         desired_method=LXMF.LXMessage.PROPAGATED)
    msg.defer_stamp = False
    router.handle_outbound(msg)
    emit("LXMF_SENT_WHILE_RECIPIENT_OFFLINE")
    # Keep the sender online during subsequent sync, so B can learn A's
    # public identity and verify the LXMF signature without private keys.
    until = time.monotonic() + 125
    while time.monotonic() < until:
        announce()
        if Path(args.delivered).exists():
            emit("LXMF_SENDER_SEES_RECEIPT")
            return
        if msg.state in (LXMF.LXMessage.FAILED, LXMF.LXMessage.REJECTED):
            raise RuntimeError("LXMF outbound failure: state=" + str(msg.state))
        time.sleep(SLEEP)
    raise TimeoutError("recipient never confirmed delivery")


def sync(args):
    storage = begin(args)
    ident = identity_file(storage / "b-identity")
    router = LXMF.LXMRouter(storagepath=str(storage))
    dest = router.register_delivery_identity(ident, display_name="lab-recipient")
    assert dest.hash == read_hash(args.recipient_addr)
    # After a relay SIGKILL, RNS may no longer know the sender announce.
    # Load a pre-verified public identity, as Akula device pairing would.
    source_hex, public_hex = wait_for(args.sender_public).split()
    source_hash = bytes.fromhex(source_hex)
    public_key = bytes.fromhex(public_hex)
    assert len(public_key) == RNS.Identity.KEYSIZE // 8
    source_identity = RNS.Identity(create_keys=False)
    assert source_identity.load_public_key(public_key)
    pinned_destination = RNS.Destination(
        source_identity, RNS.Destination.OUT, RNS.Destination.SINGLE,
        "lxmf", "delivery"
    )
    assert pinned_destination.hash == source_hash, "public key does not match sender hash"
    RNS.Identity.remember(
        RNS.Identity.full_hash(public_key), source_hash, public_key
    )
    assert RNS.Identity.recall(source_hash, _no_use=True) is not None
    emit("LXMF_TRUSTED_SENDER_IDENTITY_RESTORED")
    count = [0]

    def on_delivery(msg):
        emit("LXMF_RECEIVER_CALLBACK signature=" + str(msg.signature_validated)
             + " text=" + str(msg.content_as_string()))
        assert msg.signature_validated, "invalid or unverified signature"
        assert msg.source_hash == source_hash, "message from unpinned sender"
        assert msg.content_as_string() == MARKER, "wrong decoded payload"
        count[0] += 1
        if count[0] == 1:
            Path(args.delivered).write_text(msg.message_id.hex())
            emit("LXMF_OFFLINE_RECIPIENT_RECEIVED_VALIDATED")
        else:
            raise AssertionError("duplicate propagated message delivered twice")

    router.register_delivery_callback(on_delivery)
    node_hash = read_hash(args.node_addr)
    router.set_outbound_propagation_node(node_hash)
    next_request = 0
    next_announce = 0
    first_received = None
    until = time.monotonic() + 120
    while time.monotonic() < until:
        now = time.monotonic()
        if now >= next_announce:
            router.announce(dest.hash)
            next_announce = now + 6
        if now >= next_request:
            router.request_messages_from_propagation_node(ident)
            next_request = now + 10
        if count[0] and first_received is None:
            first_received = now
        if first_received is not None and now > first_received + 17:
            assert count[0] == 1
            emit("LXMF_SECOND_SYNC_NO_DUPLICATE_PASS")
            return
        time.sleep(SLEEP)
    raise TimeoutError("no LXMF delivery following recipient reconnect")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("role", choices=["node", "advertise", "sender", "sync"])
    ap.add_argument("--config", required=True)
    ap.add_argument("--storage", required=True)
    ap.add_argument("--node-addr")
    ap.add_argument("--recipient-addr")
    ap.add_argument("--recipient-offline")
    ap.add_argument("--sender-ready")
    ap.add_argument("--delivered")
    ap.add_argument("--sender-public")
    ap.add_argument("--expect-recovered", type=int, default=0)
    a = ap.parse_args()
    try:
        {"node": node, "advertise": advertise,
         "sender": sender, "sync": sync}[a.role](a)
    except Exception as exc:
        emit("LXMF_OFFLINE_LAB_FAIL", repr(exc))
        sys.exit(1)
