#!/usr/bin/env python3
"""Reproducible, source-pinned Roha/noq pre-Incoming limit patch.

This prepares a reviewable patch in a TEMPORARY public Roha checkout.
It never writes to the upstream GitHub repository. Apply only to
a clean checkout of the exact pinned revision (see EXPECTED).
"""
import argparse
import pathlib
import subprocess
import sys

EXPECTED = "a42ad5aef1626df80d39398e05dac6e362bf6e49"


def swap(text: str, old: str, new: str, name: str) -> str:
    count = text.count(old)
    if count != 1:
        raise ValueError(f"{name}: expected one anchor; found {count}")
    return text.replace(old, new, 1)


API = '''/// QUIC server limits applied before the transport creates Incoming objects.
///
/// The default endpoint behavior remains unchanged if these are omitted.
/// This caps outstanding unauthenticated Incoming objects and buffered
/// subsequent packets, not CPU spent parsing the first UDP/QUIC packet
/// (which is outside this buffer budget).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServerIncomingLimits {
    max_incoming: usize,
    per_incoming_bytes: u64,
    total_incoming_bytes: u64,
}

/// Invalid server-side pre-Incoming resource budgets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServerIncomingLimitsError {
    /// At least one budget is zero.
    Zero,
    /// Aggregate packet buffer allowance is smaller than one connection.
    TotalBelowPerIncoming,
}

impl ServerIncomingLimits {
    /// Construct an explicit finite policy for a receiving endpoint.
    ///
    /// The first incoming QUIC packet is not counted by noq's buffered
    /// packet limits. Applications need separate socket/UDP edge limits.
    pub fn new(
        max_incoming: usize,
        per_incoming_bytes: u64,
        total_incoming_bytes: u64,
    ) -> Result<Self, ServerIncomingLimitsError> {
        if max_incoming == 0 || per_incoming_bytes == 0 || total_incoming_bytes == 0 {
            return Err(ServerIncomingLimitsError::Zero);
        }
        if total_incoming_bytes < per_incoming_bytes {
            return Err(ServerIncomingLimitsError::TotalBelowPerIncoming);
        }
        Ok(Self { max_incoming, per_incoming_bytes, total_incoming_bytes })
    }

    /// Maximum number of pending, unaccepted transport Incoming objects.
    pub fn max_incoming(self) -> usize { self.max_incoming }
    /// Maximum buffered packet bytes for each pending Incoming.
    pub fn per_incoming_bytes(self) -> u64 { self.per_incoming_bytes }
    /// Maximum total buffered packet bytes for all pending Incoming.
    pub fn total_incoming_bytes(self) -> u64 { self.total_incoming_bytes }
}

'''


TESTS = '''
#[cfg(test)]
mod server_incoming_limits_tests {
    use super::{ServerIncomingLimits, ServerIncomingLimitsError};

    #[test]
    fn server_incoming_limits_reject_zeros_and_inconsistent_budgets() {
        for (n, per, total) in [
            (0, 4096, 8192),
            (16, 0, 8192),
            (16, 4096, 0),
        ] {
            assert_eq!(
                ServerIncomingLimits::new(n, per, total),
                Err(ServerIncomingLimitsError::Zero)
            );
        }
        assert_eq!(
            ServerIncomingLimits::new(16, 8192, 4096),
            Err(ServerIncomingLimitsError::TotalBelowPerIncoming)
        );
    }

    #[test]
    fn server_incoming_limits_preserve_exact_operator_configuration() {
        let limits = ServerIncomingLimits::new(32, 4096, 65536).unwrap();
        assert_eq!(limits.max_incoming(), 32);
        assert_eq!(limits.per_incoming_bytes(), 4096);
        assert_eq!(limits.total_incoming_bytes(), 65536);
    }
}
'''


def endpoint_patch(content: str) -> str:
    content = swap(content, "pub(crate) mod quic;\n",
                   "pub(crate) mod quic;\n\n" + API, "endpoint public API")
    content = swap(content,
                   "    transport_config: QuicTransportConfig,\n    keylog: bool,",
                   "    transport_config: QuicTransportConfig,\n    server_incoming_limits: Option<ServerIncomingLimits>,\n    keylog: bool,",
                   "builder field")
    content = swap(content,
                   "            transport_config: QuicTransportConfig::default(),\n            keylog: Default::default(),",
                   "            transport_config: QuicTransportConfig::default(),\n            server_incoming_limits: None,\n            keylog: Default::default(),",
                   "builder default")
    content = swap(content,
                   "            transport_config: self.transport_config.clone(),\n            token_key,",
                   "            transport_config: self.transport_config.clone(),\n            server_incoming_limits: self.server_incoming_limits,\n            token_key,",
                   "bind persistent policy")
    old_method = '''    pub fn transport_config(mut self, transport_config: QuicTransportConfig) -> Self {
        self.transport_config = transport_config;
        self
    }
'''
    new_method = old_method + '''
    /// Applies limits to the QUIC server *before* the transport accepts
    /// untrusted Incoming packets. They persist across set_alpns() calls.
    ///
    /// This is not a UDP/IP packet-parser or kernel-memory admission cap:
    /// it bounds pending Incoming counts and noq's subsequent packet buffers.
    pub fn server_incoming_limits(mut self, limits: ServerIncomingLimits) -> Self {
        self.server_incoming_limits = Some(limits);
        self
    }
'''
    content = swap(content, old_method, new_method, "endpoint builder API")
    if "mod server_incoming_limits_tests" in content:
        raise ValueError("already patched")
    return content + TESTS


def socket_patch(content: str) -> str:
    content = swap(
        content,
        "        LocalTransportAddr, RelayStatus, hooks::EndpointHooksList, quic::QuicTransportConfig,",
        "        LocalTransportAddr, RelayStatus, ServerIncomingLimits,\n        hooks::EndpointHooksList, quic::QuicTransportConfig,",
        "socket imported policy",
    )
    content = swap(
        content,
        "    pub(crate) transport_config: QuicTransportConfig,\n}",
        "    pub(crate) transport_config: QuicTransportConfig,\n    pub(crate) server_incoming_limits: Option<ServerIncomingLimits>,\n}",
        "immutable socket policy",
    )
    content = swap(
        content,
        "        inner.transport_config(self.transport_config.to_inner_arc());\n        inner\n    }",
        """        inner.transport_config(self.transport_config.to_inner_arc());
        // Reapply on EVERY server config construction, including changes
        // to ALPN after bind. Never silently reset to upstream defaults.
        if let Some(limits) = self.server_incoming_limits {
            inner.max_incoming(limits.max_incoming());
            inner.incoming_buffer_size(limits.per_incoming_bytes());
            inner.incoming_buffer_size_total(limits.total_incoming_bytes());
        }
        inner
    }""",
        "apply noq limits before bind",
    )
    return content


def git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.check_output(
        ["git", "-C", str(repo), *args], text=True
    ).strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("checkout", type=pathlib.Path)
    args = parser.parse_args()
    root = args.checkout.resolve()
    revision = git(root, "rev-parse", "HEAD")
    if revision != EXPECTED:
        sys.exit(f"Wrong Roha revision: {revision}; expected {EXPECTED}")
    if git(root, "status", "--porcelain"):
        sys.exit("Roha checkout must be clean; refusing to mix sources")
    targets = [
        (root / "iroh/src/endpoint.rs", endpoint_patch),
        (root / "iroh/src/socket.rs", socket_patch),
    ]
    before_after = []
    for path, transform in targets:
        original = path.read_text(encoding="utf-8")
        before_after.append((path, original, transform(original)))
    for path, _, updated in before_after:
        path.write_text(updated, encoding="utf-8")
    subprocess.run(
        ["git", "-C", str(root), "diff", "--check"], check=True
    )
    print(f"Applied pinned pre-Incoming limits to {len(targets)} Roha files at {revision}")
    print(git(root, "diff", "--stat", "--", "iroh/src/endpoint.rs", "iroh/src/socket.rs"))


if __name__ == "__main__":
    main()
