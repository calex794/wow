//! SQLite-free copy of the WOW W3 lab cryptographic boundary.
//! This is a controlled extraction from src/crypto_w3.rs and src/trust_w3.rs.
//! No transport, persistent replay ledger, authorization to read files or W4 receipt.
#![forbid(unsafe_code)]
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;
pub mod crypto_w3;
pub mod trust_w3;
