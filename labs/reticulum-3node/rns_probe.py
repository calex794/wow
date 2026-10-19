#!/usr/bin/env python3
"""Isolated real Reticulum path/proof test (not a mock and not Akula Sync)."""
import argparse
import os
import sys
import time
from pathlib import Path

import RNS

APP = "akula_rns_lab"
ASPECT = "transport_proof"
PAYLOAD = b"AKULA_RNS_THROUGH_VOLUNTARY_TRANSPORT_NODE"


def log(msg):
    print(msg, flush=True)


def receiver(args):
    RNS.Reticulum(args.config)
    ident = RNS.Identity()
    destination = RNS.Destination(
        ident, RNS.Destination.IN, RNS.Destination.SINGLE, APP, ASPECT
    )
    destination.set_proof_strategy(RNS.Destination.PROVE_ALL)

    def on_packet(data, packet):
        if data != PAYLOAD:
            log("RECEIVER_INVALID_DATA")
            return
        log("RNS_RECEIVER_PAYLOAD_OK")
        Path(args.done).write_text("received\n", encoding="ascii")

    destination.set_packet_callback(on_packet)
    Path(args.address).write_text(destination.hash.hex(), encoding="ascii")
    log("RECEIVER_READY destination=" + destination.hash.hex())
    for _ in range(30):
        destination.announce()
        if Path(args.done).exists():
            time.sleep(1.0)
            return
        time.sleep(3.0)
    raise TimeoutError("no RNS packet delivered to receiver")


def sender(args):
    RNS.Reticulum(args.config)
    target = bytes.fromhex(Path(args.address).read_text().strip())
    deadline = time.monotonic() + args.timeout
    while not RNS.Transport.has_path(target) and time.monotonic() < deadline:
        RNS.Transport.request_path(target)
        time.sleep(2.0)
    if not RNS.Transport.has_path(target):
        log("RNS_PATH_NOT_FOUND")
        if args.expect_failure:
            return
        raise TimeoutError("cannot find destination via transport node")

    hops = RNS.Transport.hops_to(target)
    log(f"RNS_PATH_FOUND hops={hops} next_hop={RNS.Transport.next_hop(target)}")
    if hops < 2 and not args.expect_failure:
        raise AssertionError("expected at least two Reticulum hops via T")

    ident = RNS.Identity.recall(target)
    assert ident is not None, "missing announced destination identity"
    destination = RNS.Destination(
        ident, RNS.Destination.OUT, RNS.Destination.SINGLE, APP, ASPECT
    )
    packet = RNS.Packet(destination, PAYLOAD)
    receipt = packet.send()
    assert receipt is not False and receipt is not None
    receipt.set_timeout(10.0)
    deadline = time.monotonic() + 17.0
    while time.monotonic() < deadline:
        if receipt.status == RNS.PacketReceipt.DELIVERED:
            if args.expect_failure:
                raise AssertionError("forbidden path delivered despite T being off")
            log(f"RNS_TRANSPORT_PROOF_PASS hops={hops} rtt={receipt.get_rtt():.3f}")
            return
        if receipt.status == RNS.PacketReceipt.FAILED:
            break
        time.sleep(0.2)
    if args.expect_failure:
        log("RNS_TRANSPORT_DOWN_NO_PROOF_OK")
        return
    raise TimeoutError("RNS packet was not proven delivered")


def transport(args):
    RNS.Reticulum(args.config)
    assert RNS.Reticulum.transport_enabled(), "T must be explicitly enabled"
    log("RNS_TRANSPORT_NODE_ENABLED")
    while True:
        time.sleep(5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("role", choices=["transport", "receive", "send"])
    parser.add_argument("--config", required=True)
    parser.add_argument("--address")
    parser.add_argument("--done")
    parser.add_argument("--timeout", type=float, default=70.0)
    parser.add_argument("--expect-failure", action="store_true")
    args = parser.parse_args()
    try:
        {"transport": transport, "receive": receiver, "send": sender}[args.role](args)
    except Exception as e:
        log("RNS_LAB_FAIL: " + repr(e))
        sys.exit(1)
