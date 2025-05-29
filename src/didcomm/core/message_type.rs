use common_macros::DebugError;
use lazy_static::lazy_static;
use regex::{Match, Regex};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use snafu::Snafu;
use std::fmt::Display;
use strum_macros::EnumIter;
use tracing::{debug, instrument, Level};

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("Incorrect message type: {type_}"))]
    IncorrectMessageType { type_: String },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct MessageType {
    pub prefix: MessageTypePrefix,
    pub family: String,
    pub version: String,
    pub type_: String,
}

impl<'de> Deserialize<'de> for MessageType {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer).map_err(de::Error::custom)?;

        match value.as_str() {
            Some(type_) => {
                let (prefix, family, version, type_) =
                    parse_message_type(type_).map_err(de::Error::custom)?;
                Ok(MessageType {
                    prefix: MessageTypePrefix::from(prefix),
                    family,
                    version,
                    type_,
                })
            }
            val => Err(de::Error::custom(format!(
                "Unexpected @type field structure: {:?}",
                val
            ))),
        }
    }
}

impl Serialize for MessageType {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let value = serde_json::Value::String(self.to_string());
        value.serialize(serializer)
    }
}

#[instrument(level = Level::TRACE, skip_all, err())]
pub fn parse_message_type(message_type: &str) -> Result<(String, String, String, String)> {
    debug!("parse_message_type >>> message_type: {:?}", message_type);

    lazy_static! {
        static ref RE: Regex = Regex::new(
            r"(?x)
            (?P<prefix>did:\w+:\w+;spec|https://didcomm.org)/
            (?P<family>.*)/
            (?P<version>.*)/
            (?P<type>.*)"
        )
        .unwrap();
    }

    let message_type = RE
        .captures(message_type)
        .and_then(|cap| {
            let prefix = cap.name("prefix").as_ref().map(Match::as_str);
            let family = cap.name("family").as_ref().map(Match::as_str);
            let version = cap.name("version").as_ref().map(Match::as_str);
            let type_ = cap.name("type").as_ref().map(Match::as_str);

            match (prefix, family, version, type_) {
                (Some(prefix), Some(family), Some(version), Some(type_)) => Some((
                    prefix.to_string(),
                    family.to_string(),
                    version.to_string(),
                    type_.to_string(),
                )),
                _ => None,
            }
        })
        .ok_or(
            IncorrectMessageTypeSnafu {
                type_: message_type,
            }
            .build(),
        )?;

    debug!("parse_message_type <<< message_type: {:?}", message_type);

    Ok(message_type)
}

impl Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = format!(
            "{}/{}/{}/{}",
            self.prefix, self.family, self.version, self.type_
        );
        write!(f, "{}", str)
    }
}

#[derive(Default, Debug, Deserialize, Serialize, Clone, PartialEq, EnumIter)]
pub enum MessageTypePrefix {
    #[default]
    DID,
    Endpoint,
}

impl From<String> for MessageTypePrefix {
    fn from(family: String) -> Self {
        match family.as_str() {
            "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec" => MessageTypePrefix::DID,
            "https://didcomm.org" => MessageTypePrefix::Endpoint,
            _ => MessageTypePrefix::DID,
        }
    }
}

impl Display for MessageTypePrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let str = match self {
            MessageTypePrefix::DID => "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec".to_string(),
            MessageTypePrefix::Endpoint => "https://didcomm.org".to_string(),
        };
        write!(f, "{}", str)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    fn _message_type_with_did() -> &'static str {
        "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/connections/1.0/invitation"
    }

    fn _message_type_with_endpoint() -> &'static str {
        "https://didcomm.org/connections/1.0/invitation"
    }

    #[test]
    fn test_parse_message_type_with_did() {
        let type_ = _message_type_with_did();
        let message_type: MessageType =
            ::serde_json::from_value(serde_json::Value::String(type_.to_string())).unwrap();
        let expected = MessageType {
            prefix: MessageTypePrefix::DID,
            family: "connections".to_string(),
            version: "1.0".to_string(),
            type_: "invitation".to_string(),
        };
        assert_eq!(expected, message_type);
        assert_eq!(type_.to_string(), message_type.to_string());
    }

    #[test]
    fn test_parse_message_type_with_endpoint() {
        let type_ = _message_type_with_endpoint();
        let message_type: MessageType =
            ::serde_json::from_value(serde_json::Value::String(type_.to_string())).unwrap();
        let expected = MessageType {
            prefix: MessageTypePrefix::Endpoint,
            family: "connections".to_string(),
            version: "1.0".to_string(),
            type_: "invitation".to_string(),
        };
        assert_eq!(expected, message_type);
        assert_eq!(type_.to_string(), message_type.to_string());
    }
}
