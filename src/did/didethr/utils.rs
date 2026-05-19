use crate::did::ResolutionError;
use std::{collections::HashSet, hash::Hash};

pub fn format_bytes32_string(string: &str) -> Result<[u8; 32], ResolutionError> {
    let str_bytes = string.as_bytes();
    if str_bytes.len() > 32 {
        return Err(ResolutionError::Internal(
            "Unable to represent string as bytes32".to_string(),
        ));
    }
    let mut bytes32: [u8; 32] = [0u8; 32];
    bytes32[..str_bytes.len()].copy_from_slice(str_bytes);
    Ok(bytes32)
}

pub fn parse_bytes32_string(bytes: &[u8]) -> Result<&str, ResolutionError> {
    let mut length = 0;
    while length < 32 && length < bytes.len() && bytes[length] != 0 {
        length += 1;
    }
    std::str::from_utf8(&bytes[..length]).map_err(|err| {
        ResolutionError::Internal(format!(
            "Unable to decode string from bytes. Err: {:?}",
            err
        ))
    })
}

pub fn is_unique<T>(iter: T) -> bool
where
    T: IntoIterator,
    T::Item: Eq + Hash,
{
    let mut unique = HashSet::new();
    iter.into_iter().all(|item| unique.insert(item))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_bytes32_string_pads_short_input_with_zeros() {
        let bytes = format_bytes32_string("abc").unwrap();

        assert_eq!(&bytes[..3], b"abc");
        assert!(bytes[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn format_bytes32_string_accepts_exactly_32_bytes_unchanged() {
        let input: String = "x".repeat(32);

        let bytes = format_bytes32_string(&input).unwrap();

        assert_eq!(&bytes[..], input.as_bytes());
    }

    #[test]
    #[should_panic(expected = "Unable to represent string as bytes32")]
    fn format_bytes32_string_rejects_input_longer_than_32_bytes() {
        let input: String = "y".repeat(33);

        format_bytes32_string(&input).unwrap();
    }

    #[test]
    fn parse_bytes32_string_truncates_at_first_null_byte() {
        let mut bytes = [0u8; 32];
        bytes[..5].copy_from_slice(b"hello");

        let s = parse_bytes32_string(&bytes).unwrap();

        assert_eq!(s, "hello");
    }

    #[test]
    fn parse_bytes32_string_returns_full_string_when_no_null_in_first_32_bytes() {
        let bytes: [u8; 32] = [b'A'; 32];

        let s = parse_bytes32_string(&bytes).unwrap();

        assert_eq!(s.len(), 32);
        assert!(s.chars().all(|c| c == 'A'));
    }

    #[test]
    #[should_panic(expected = "Unable to decode string from bytes")]
    fn parse_bytes32_string_rejects_invalid_utf8() {
        // 0xFF is never valid as a leading UTF-8 byte.
        let bytes = [0xFFu8, b'a', b'b'];

        parse_bytes32_string(&bytes).unwrap();
    }

    #[test]
    fn is_unique_returns_true_for_distinct_items() {
        assert!(is_unique(vec![1, 2, 3, 4]));
    }

    #[test]
    fn is_unique_returns_false_when_duplicates_present() {
        assert!(!is_unique(vec![1, 2, 3, 2]));
    }

    #[test]
    fn is_unique_returns_true_for_empty_iterator() {
        let empty: Vec<i32> = vec![];
        assert!(is_unique(empty));
    }
}
