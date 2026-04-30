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
