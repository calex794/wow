// Injected ONLY into noq-proto/src/frame.rs of the exact pinned calex794/noq
// source in CI. This is a research fixture, not a shipped QUIC patch.
// The tests call the real private read_ack_blocks implementation.

#[cfg(test)]
mod fork_audit_ack_range_boundary {
    use super::{read_ack_blocks, Bytes};
    use alloc::vec::Vec;

    #[test]
    fn huge_varint_count_with_no_ranges_returns_error() {
        // QUIC 8-byte VarInt of 2^62 - 1. No ACK range bytes follow.
        // The real parser must fail on exhausted input rather than loop
        // over the attacker-supplied counter.
        let mut encoded = Bytes::from_static(&[0xff; 8]);
        assert!(read_ack_blocks(&mut encoded, 42).is_err());
        assert!(encoded.is_empty());
    }

    #[test]
    fn valid_513_extra_ranges_are_accepted_by_pinned_parser() {
        // 513 ACK Range Count (two-byte QUIC VarInt), plus 514 one-packet
        // ranges separated by one omitted packet. Encoded ranges fit into
        // 1029 bytes, i.e. below a common 1200-byte QUIC datagram budget
        // before packet framing. A hard max of 512 changes behavior.
        let mut encoded = Vec::with_capacity(1029);
        encoded.extend_from_slice(&[0x42, 0x01]);
        for _ in 0..513 {
            encoded.extend_from_slice(&[0x00, 0x00]); // range=0, gap=0
        }
        encoded.push(0x00); // final range=0, no following gap
        assert_eq!(encoded.len(), 1029);

        let mut bytes = Bytes::from(encoded);
        let parsed = read_ack_blocks(&mut bytes, 1200);
        assert!(parsed.is_ok(), "pinned parser rejected 513 extra ranges: {parsed:?}");
        assert!(bytes.is_empty());
    }

    #[test]
    fn zero_extra_ranges_remains_valid() {
        let mut bytes = Bytes::from_static(&[0x00, 0x00]);
        assert!(read_ack_blocks(&mut bytes, 0).is_ok());
        assert!(bytes.is_empty());
    }
}
