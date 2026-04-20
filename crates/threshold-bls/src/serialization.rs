//! Bounded bincode (de)serialization.
//!
//! Wraps `bincode::deserialize` / `bincode::deserialize_from` with a fixed input
//! size limit so an attacker-crafted length prefix on a `Vec` field cannot
//! trigger an exabyte-scale allocation. Encoding options otherwise match
//! `bincode::deserialize` exactly (little-endian fixint), preserving wire
//! compatibility with previously serialized data.

use bincode::Options;
use serde::{de::DeserializeOwned, Deserialize};
use std::io::Read;

/// Upper bound (in bytes) on any single deserialize call.
///
/// 1 MiB comfortably covers a `Poly<PublicKey>` at threshold on the order of
/// 10k participants while blocking `u64::MAX`-style length-prefix attacks.
pub const MAX_DESERIALIZE_BYTES: u64 = 1 << 20;

fn options() -> impl Options {
    // Match `bincode::deserialize` / `bincode::deserialize_from` exactly:
    // fixint encoding, little-endian (DefaultOptions), trailing bytes allowed.
    // Only add the size limit on top, so the helper is a true drop-in.
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .allow_trailing_bytes()
        .with_limit(MAX_DESERIALIZE_BYTES)
}

/// Drop-in replacement for `bincode::deserialize` that enforces
/// [`MAX_DESERIALIZE_BYTES`].
pub fn deserialize<'a, T: Deserialize<'a>>(bytes: &'a [u8]) -> bincode::Result<T> {
    options().deserialize(bytes)
}

/// Drop-in replacement for `bincode::deserialize_from` that enforces
/// [`MAX_DESERIALIZE_BYTES`].
pub fn deserialize_from<R: Read, T: DeserializeOwned>(reader: R) -> bincode::Result<T> {
    options().deserialize_from(reader)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_normal_input() {
        let v: Vec<u8> = vec![1, 2, 3, 4];
        let bytes = bincode::serialize(&v).unwrap();
        let round: Vec<u8> = deserialize(&bytes).unwrap();
        assert_eq!(round, v);
    }

    #[test]
    fn rejects_oversized_length_prefix() {
        // `Vec<u8>` bincode format: u64 little-endian length, then payload.
        // Claim a 2^63-byte vec in only a few bytes of buffer. Without a limit
        // bincode attempts to allocate ~8 EiB; the bounded version must reject.
        let mut evil = (i64::MAX as u64).to_le_bytes().to_vec();
        evil.extend_from_slice(&[0u8; 8]);
        let result: Result<Vec<u8>, _> = deserialize(&evil);
        assert!(result.is_err(), "oversized length prefix must be rejected");
    }

    #[test]
    fn rejects_length_just_over_limit() {
        let claimed = MAX_DESERIALIZE_BYTES + 1;
        let mut evil = claimed.to_le_bytes().to_vec();
        evil.extend_from_slice(&[0u8; 8]);
        let result: Result<Vec<u8>, _> = deserialize(&evil);
        assert!(
            result.is_err(),
            "length over MAX_DESERIALIZE_BYTES must be rejected"
        );
    }

    #[test]
    fn deserialize_from_also_bounded() {
        let mut evil = (i64::MAX as u64).to_le_bytes().to_vec();
        evil.extend_from_slice(&[0u8; 8]);
        let result: Result<Vec<u8>, _> = deserialize_from(&evil[..]);
        assert!(
            result.is_err(),
            "deserialize_from must also enforce the limit"
        );
    }

    #[test]
    fn allows_trailing_bytes_like_bincode_top_level() {
        // `bincode::deserialize` (the free function) uses `allow_trailing_bytes()`;
        // the bounded helper must match so it's a true drop-in.
        let v: Vec<u8> = vec![1, 2, 3];
        let mut bytes = bincode::serialize(&v).unwrap();
        bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC]); // trailing garbage
        let round: Vec<u8> = deserialize(&bytes).unwrap();
        assert_eq!(round, v);
    }

    #[test]
    fn rejects_nested_vec_oversized_inner_length() {
        // `Eval<Vec<u8>>` is the actual shape passed through `partial_verify` and
        // `aggregate`. A small outer envelope with a malicious inner `Vec<u8>`
        // length claiming u64::MAX must be rejected — this is the realistic
        // attack shape, not just a bare `Vec<u8>`.
        use crate::poly::Eval;
        let mut evil: Vec<u8> = Vec::new();
        evil.extend_from_slice(&u64::MAX.to_le_bytes()); // inner Vec<u8> claimed length
        evil.extend_from_slice(&0u32.to_le_bytes()); // Idx
        let result: bincode::Result<Eval<Vec<u8>>> = deserialize(&evil);
        assert!(result.is_err(), "nested oversized Vec must be rejected");
    }
}
