//! Standalone arithmetic regression for the proposed ACK-delay shift
//! seen in emrul/noq@552e75c. No fork code is executed or adopted.
//!
//! Rust checked_shl() rejects an INVALID SHIFT AMOUNT; it does not
//! reject numeric bits lost from the shifted value. This matters for
//! converting peer-supplied QUIC ACK delay to microseconds.
use std::{cmp, time::Duration};

#[test]
fn checked_shl_does_not_detect_lost_high_bits() {
    // Both are valid values: ACK delay VarInt <= 2^62-1, peer exponent <=20.
    let delay_varint: u64 = 1u64 << 44;
    let exponent: u32 = 20;
    // Product would be 2^64 and does not fit u64.
    assert_eq!(delay_varint.checked_shl(exponent), Some(0));
    // Saturating construction MUST treat value overflow as overflow.
    let scaled = delay_varint.checked_mul(1u64 << exponent)
        .unwrap_or(u64::MAX);
    assert_eq!(scaled, u64::MAX);

    let peer_max_ack_delay = Duration::from_millis(25);
    let proposed = cmp::min(
        Duration::from_micros(delay_varint.checked_shl(exponent).unwrap_or(u64::MAX)),
        peer_max_ack_delay,
    );
    let saturated = cmp::min(Duration::from_micros(scaled), peer_max_ack_delay);
    assert_eq!(proposed, Duration::ZERO);
    assert_eq!(saturated, peer_max_ack_delay);
}

#[test]
fn safe_ack_delay_multiplication_preserves_ordinary_values() {
    let encoded: u64 = 1_250;
    let exponent: u32 = 3;
    let scaled = encoded.checked_mul(1u64 << exponent).unwrap_or(u64::MAX);
    assert_eq!(scaled, 10_000);
    assert_eq!(Duration::from_micros(scaled), Duration::from_millis(10));
}
