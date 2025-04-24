use common_macros::DebugError;
use regex::Regex;
use snafu::{ResultExt, Snafu};

#[derive(Snafu, DebugError)]
#[snafu(display("Incorrect message type"))]
pub struct Error {
    source: regex::Error,
}

pub struct ParsedMessageType {
    pub doc_uri: String,
    pub protocol_name: String,
    pub protocol_version: String,
    pub message_type_name: String,
}

impl ParsedMessageType {
    /// Parse a message type to extract protocol information
    ///
    /// Message types typically follow the format:
    /// <https://didcomm.org/{protocol}/{version}/{type}>
    ///
    /// # Arguments
    /// * `message_type` - The message type string
    ///
    /// # Returns
    ///
    /// * [ParsedMessageType] if parsed successfully
    pub fn from_message_type(type_: &str) -> Result<ParsedMessageType, Error> {
        let regex = Regex::new("(.*?)([a-z0-9._-]+)/(\\d[^/]*)/([a-z0-9._-]+)$").context(Snafu)?;

        let captures = regex.captures(type_).unwrap();

        let doc_uri = captures.get(1).map_or("", |m| m.as_str()).to_string();
        let protocol_name = captures.get(2).map_or("", |m| m.as_str()).to_string();
        let protocol_version = captures.get(3).map_or("", |m| m.as_str()).to_string();
        let message_type_name = captures.get(4).map_or("", |m| m.as_str()).to_string();

        Ok(ParsedMessageType {
            doc_uri,
            protocol_name,
            protocol_version,
            message_type_name,
        })
    }
}
