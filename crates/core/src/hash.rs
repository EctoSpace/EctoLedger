use sha2::{Digest, Sha256};

pub const GENESIS_PREVIOUS_HASH: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Compute a hex-encoded hash of `input`.
///
/// When the `hash-blake3` feature is enabled, uses BLAKE3 (256-bit);
/// otherwise falls back to SHA-256.  Both produce 64-char hex strings.
#[inline]
pub fn sha256_hex(input: &[u8]) -> String {
    #[cfg(feature = "hash-blake3")]
    {
        let hash = blake3::hash(input);
        hash.to_hex().to_string()
    }
    #[cfg(not(feature = "hash-blake3"))]
    {
        let hash = Sha256::digest(input);
        hex::encode(hash)
    }
}

/// Compute a hex-encoded SHA-256 hash (always SHA-256, independent of
/// `hash-blake3`).  Used during chain verification to attempt legacy
/// fallback when the current hash algorithm doesn't match.
#[inline]
pub fn sha256_hex_legacy(input: &[u8]) -> String {
    let hash = Sha256::digest(input);
    hex::encode(hash)
}

/// SHA-256(len(a) || a || len(b) || b) — used by the attestation layer to
/// commit to a prompt/response pair without exposing either value directly.
///
/// Each input is prefixed with its 8-byte big-endian length to prevent
/// boundary-manipulation collisions (e.g. shifting bytes between `a` and `b`).
#[inline]
pub fn sha256_pair(a: &[u8], b: &[u8]) -> String {
    let mut hasher = <Sha256 as Digest>::new();
    hasher.update((a.len() as u64).to_be_bytes());
    hasher.update(a);
    hasher.update((b.len() as u64).to_be_bytes());
    hasher.update(b);
    hex::encode(hasher.finalize())
}

pub fn content_hash_input(
    previous_hash: &str,
    sequence: i64,
    payload_json: &str,
    session_id: Option<&str>,
    created_at: Option<&str>,
) -> Vec<u8> {
    // Use null-byte delimiters between fields to prevent boundary-manipulation
    // collisions (e.g. sequence=1,payload="23{}" vs sequence=12,payload="3{}").
    let seq_str = sequence.to_string();
    let sid_len = session_id.map_or(0, |s| 1 + s.len());
    let ts_len = created_at.map_or(0, |t| 1 + t.len());
    let mut out = Vec::with_capacity(
        previous_hash.len() + 1 + seq_str.len() + 1 + payload_json.len() + sid_len + ts_len,
    );
    out.extend_from_slice(previous_hash.as_bytes());
    out.push(0x00);
    out.extend_from_slice(seq_str.as_bytes());
    out.push(0x00);
    out.extend_from_slice(payload_json.as_bytes());
    // When a session_id is provided, append it with a null-byte delimiter so
    // the event is cryptographically bound to this session — preventing
    // cross-session replay attacks (TM-2).
    if let Some(sid) = session_id {
        out.push(0x00);
        out.extend_from_slice(sid.as_bytes());
    }
    // When a timestamp is provided, append it with a null-byte delimiter so
    // the event is cryptographically bound to its creation time — preventing
    // timestamp manipulation after the fact (TM-2b).
    if let Some(ts) = created_at {
        out.push(0x00);
        out.extend_from_slice(ts.as_bytes());
    }
    out
}

pub fn compute_content_hash(
    previous_hash: &str,
    sequence: i64,
    payload_json: &str,
    session_id: Option<&str>,
    created_at: Option<&str>,
) -> String {
    let input = content_hash_input(
        previous_hash,
        sequence,
        payload_json,
        session_id,
        created_at,
    );
    sha256_hex(&input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn genesis_hash_is_64_hex_chars() {
        let h = compute_content_hash(
            GENESIS_PREVIOUS_HASH,
            0,
            r#"{"type":"genesis","message":"test"}"#,
            None,
            None,
        );
        assert_eq!(h.len(), 64);
        assert!(h.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn same_input_same_hash() {
        let a = compute_content_hash(GENESIS_PREVIOUS_HASH, 1, "{}", None, None);
        let b = compute_content_hash(GENESIS_PREVIOUS_HASH, 1, "{}", None, None);
        assert_eq!(a, b);
    }

    /// Regression: previously sequence/payload boundary shift produced collisions.
    #[test]
    fn no_sequence_payload_collision() {
        let a = compute_content_hash(GENESIS_PREVIOUS_HASH, 1, "23{}", None, None);
        let b = compute_content_hash(GENESIS_PREVIOUS_HASH, 12, "3{}", None, None);
        let c = compute_content_hash(GENESIS_PREVIOUS_HASH, 123, "{}", None, None);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }

    /// TM-2: session_id included in hash prevents cross-session replay.
    #[test]
    fn session_id_changes_hash() {
        let without = compute_content_hash(GENESIS_PREVIOUS_HASH, 0, "{}", None, None);
        let with_a =
            compute_content_hash(GENESIS_PREVIOUS_HASH, 0, "{}", Some("aaaa-bbbb-cccc"), None);
        let with_b =
            compute_content_hash(GENESIS_PREVIOUS_HASH, 0, "{}", Some("xxxx-yyyy-zzzz"), None);
        assert_ne!(without, with_a, "session_id must change the hash");
        assert_ne!(
            with_a, with_b,
            "different sessions must produce different hashes"
        );
    }

    /// TM-2b: created_at timestamp included in hash prevents timestamp manipulation.
    #[test]
    fn timestamp_changes_hash() {
        let without = compute_content_hash(GENESIS_PREVIOUS_HASH, 0, "{}", None, None);
        let with_ts_a = compute_content_hash(
            GENESIS_PREVIOUS_HASH,
            0,
            "{}",
            None,
            Some("2025-01-01T00:00:00Z"),
        );
        let with_ts_b = compute_content_hash(
            GENESIS_PREVIOUS_HASH,
            0,
            "{}",
            None,
            Some("2025-06-01T12:00:00Z"),
        );
        assert_ne!(without, with_ts_a, "timestamp must change the hash");
        assert_ne!(
            with_ts_a, with_ts_b,
            "different timestamps must produce different hashes"
        );
    }

    /// TM-2b: session_id AND timestamp together are both bound.
    #[test]
    fn session_and_timestamp_combined() {
        let base = compute_content_hash(
            GENESIS_PREVIOUS_HASH,
            0,
            "{}",
            Some("sess-1"),
            Some("2025-01-01T00:00:00Z"),
        );
        let diff_ts = compute_content_hash(
            GENESIS_PREVIOUS_HASH,
            0,
            "{}",
            Some("sess-1"),
            Some("2025-06-01T00:00:00Z"),
        );
        let diff_sid = compute_content_hash(
            GENESIS_PREVIOUS_HASH,
            0,
            "{}",
            Some("sess-2"),
            Some("2025-01-01T00:00:00Z"),
        );
        assert_ne!(base, diff_ts);
        assert_ne!(base, diff_sid);
        assert_ne!(diff_ts, diff_sid);
    }

    /// Regression: sha256_pair boundary shift must produce distinct hashes.
    #[test]
    fn sha256_pair_no_boundary_collision() {
        let a = sha256_pair(b"prompt_text", b"response");
        let b_hash = sha256_pair(b"prompt_tex", b"tresponse");
        assert_ne!(a, b_hash);
    }
}
