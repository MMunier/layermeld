//! PAX extended-header record encoding (POSIX.1-2001).
//!
//! Each record has the form `<len> <key>=<value>\n`, where `<len>` is the
//! decimal byte length of the record *including the digits of `<len>`
//! itself* — making the length field self-referential. This module
//! computes that length correctly and emits the record byte-for-byte.
//!
//! Records are concatenated to form the body of an `XHeader` (`type=x`)
//! extended-header tar entry, padded to a 512-byte block boundary by the
//! writer in [`crate::tar_io::writer`]. Spec 02 §2.4 mandates this
//! dialect for all output layers.

/// Encode a single PAX record `<len> <key>=<value>\n`.
///
/// `key` and `value` are arbitrary byte strings; PAX permits any bytes
/// other than NUL in records, although by convention `key` is ASCII.
#[must_use]
pub fn encode_record(key: &[u8], value: &[u8]) -> Vec<u8> {
    // Bytes that are *not* the leading length field:
    //   1 separator space + key + '=' + value + trailing newline.
    let body = key.len() + value.len() + 3;

    // The length field is self-referential: adding more digits to the
    // length increases the total length, which may need yet more digits.
    // Iterate digit count until the value stabilises (≤ 1 step in practice).
    let mut digits = 1usize;
    let total = loop {
        let total = body + digits;
        if decimal_len(total) == digits {
            break total;
        }
        digits += 1;
    };

    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(total.to_string().as_bytes());
    out.push(b' ');
    out.extend_from_slice(key);
    out.push(b'=');
    out.extend_from_slice(value);
    out.push(b'\n');
    debug_assert_eq!(out.len(), total);
    out
}

/// Encode a sequence of PAX records back-to-back.
///
/// Order matters: extractors apply records left-to-right and later keys
/// override earlier ones. Callers are responsible for de-duplicating.
#[must_use]
pub fn encode_records(records: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in records {
        out.extend_from_slice(&encode_record(k, v));
    }
    out
}

/// Decimal width of a non-negative integer.
fn decimal_len(mut n: usize) -> usize {
    if n == 0 {
        return 1;
    }
    let mut d = 0;
    while n > 0 {
        n /= 10;
        d += 1;
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference implementation: parse `<len> <key>=<value>\n` and
    /// validate the self-referential length.
    fn parse_one(input: &[u8]) -> (usize, &[u8], &[u8], &[u8]) {
        let space = input.iter().position(|&b| b == b' ').unwrap();
        let len: usize = std::str::from_utf8(&input[..space]).unwrap().parse().unwrap();
        let record = &input[..len];
        let body = &record[space + 1..];
        let eq = body.iter().position(|&b| b == b'=').unwrap();
        let nl = body.len() - 1;
        assert_eq!(body[nl], b'\n');
        (len, &body[..eq], &body[eq + 1..nl], &input[len..])
    }

    #[test]
    fn short_record_round_trips() {
        let r = encode_record(b"path", b"/etc/hostname");
        let (len, key, value, rest) = parse_one(&r);
        assert_eq!(len, r.len());
        assert_eq!(key, b"path");
        assert_eq!(value, b"/etc/hostname");
        assert!(rest.is_empty());
    }

    #[test]
    fn record_length_is_self_referential() {
        // Force a value long enough that the length field grows from 2
        // digits to 3, then verify the parser still accepts it. This is
        // the boundary where the naive "length excludes itself" encoding
        // would silently miscount.
        // 1-digit boundary: with body=8 the candidate total 9 is 1
        // digit (stable). Bump value length by one and the candidate
        // total becomes 10, which now needs 2 digits — the function
        // must detect that and re-iterate.
        let r = encode_record(b"k", &[b'a'; 5]);
        // body = 1+5+3 = 9; +1 digit = 10 → 2 digits → stable at +2 digits = 11.
        assert_eq!(r.len(), 11);
        let (len, _, val, _) = parse_one(&r);
        assert_eq!(len, 11);
        assert_eq!(val.len(), 5);
        // Two-digit stable case: body=94 → 94+2=96 fits in 2 digits.
        let r = encode_record(b"k", &[b'a'; 90]);
        assert_eq!(r.len(), 96);
    }

    #[test]
    fn binary_value_passes_through() {
        // PAX records are byte-strings; values may contain NUL-free
        // arbitrary bytes (xattr payloads commonly do).
        let value: Vec<u8> = (1..=128).collect();
        let r = encode_record(b"SCHILY.xattr.user.bin", &value);
        let (_, key, val, _) = parse_one(&r);
        assert_eq!(key, b"SCHILY.xattr.user.bin");
        assert_eq!(val, value.as_slice());
    }

    #[test]
    fn multiple_records_concatenate() {
        let bytes = encode_records(&[
            (b"path".to_vec(), b"/long/path".to_vec()),
            (b"linkpath".to_vec(), b"/target".to_vec()),
        ]);
        let (_, k1, v1, rest) = parse_one(&bytes);
        assert_eq!(k1, b"path");
        assert_eq!(v1, b"/long/path");
        let (_, k2, v2, rest) = parse_one(rest);
        assert_eq!(k2, b"linkpath");
        assert_eq!(v2, b"/target");
        assert!(rest.is_empty());
    }

    #[test]
    fn decimal_len_matches_to_string() {
        for n in [0usize, 1, 9, 10, 99, 100, 999, 1000, 12345, 1_000_000] {
            assert_eq!(decimal_len(n), n.to_string().len(), "n={n}");
        }
    }
}
