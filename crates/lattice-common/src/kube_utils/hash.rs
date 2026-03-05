//! Deterministic hashing utilities.

/// Compute a deterministic hash of the input string, returning a 16-char hex digest.
///
/// Uses truncated SHA-256 for stability across Rust toolchain versions.
/// `DefaultHasher` is NOT guaranteed stable across Rust releases, so this
/// function should be used whenever the hash is persisted (e.g., K8s annotations).
pub fn deterministic_hash(input: &str) -> String {
    use aws_lc_rs::digest;
    let hash = digest::digest(&digest::SHA256, input.as_bytes());
    // Take first 8 bytes (16 hex chars) for a compact annotation value
    hash.as_ref()[..8]
        .iter()
        .fold(String::with_capacity(16), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
            s
        })
}

/// Compute a full SHA-256 hash of arbitrary bytes.
///
/// Returns the 32-byte digest. Uses aws-lc-rs for FIPS compliance.
pub fn sha256(data: &[u8]) -> Vec<u8> {
    use aws_lc_rs::digest;
    digest::digest(&digest::SHA256, data).as_ref().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_produces_32_byte_output() {
        let hash = sha256(b"hello world");
        assert_eq!(hash.len(), 32, "SHA-256 must produce exactly 32 bytes");
    }

    #[test]
    fn sha256_is_deterministic() {
        let hash1 = sha256(b"deterministic input");
        let hash2 = sha256(b"deterministic input");
        assert_eq!(hash1, hash2, "Same input must produce identical hashes");
    }

    #[test]
    fn sha256_different_inputs_produce_different_hashes() {
        let hash_a = sha256(b"input a");
        let hash_b = sha256(b"input b");
        assert_ne!(
            hash_a, hash_b,
            "Different inputs should produce different hashes"
        );
    }

    #[test]
    fn sha256_empty_input_produces_valid_hash() {
        let hash = sha256(b"");
        assert_eq!(hash.len(), 32, "Empty input must still produce 32 bytes");
        // SHA-256 of empty string is a well-known constant
        let expected_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let actual_hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            actual_hex, expected_hex,
            "Empty-string SHA-256 must match the known digest"
        );
    }

    #[test]
    fn deterministic_hash_produces_16_char_hex() {
        let hash = deterministic_hash("test input");
        assert_eq!(hash.len(), 16, "Truncated hash must be 16 hex characters");
        assert!(
            hash.chars().all(|c| c.is_ascii_hexdigit()),
            "All characters must be hex digits"
        );
    }

    #[test]
    fn deterministic_hash_is_stable() {
        let hash1 = deterministic_hash("stable");
        let hash2 = deterministic_hash("stable");
        assert_eq!(
            hash1, hash2,
            "Same input must produce identical truncated hashes"
        );
    }
}
