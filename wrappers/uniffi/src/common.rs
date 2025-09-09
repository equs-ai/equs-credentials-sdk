use serde::{Deserialize, Deserializer};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(uniffi::Enum, Debug)]
pub enum OID4VCIProtocolErrorType {
    InvalidToken,
    InvalidCredentialRequest,
    UnknownCredentialConfiguration,
    UnknownCredentialIdentifier,
    InvalidProof,
    InvalidEncryptionParameters,
}

#[derive(uniffi::Error, Debug)]
pub enum Error {
    OID4VPHolder(String),
    OID4VCIInternal(String),
    OID4VCIProtocol {
        error: OID4VCIProtocolErrorType,
        error_description: Option<String>,
    },
    DIDResolution {
        details: String,
    },
    DIDResolver(String),
    Vault(String),
    Kms(String),
    KeyHandle(String),
    HttpAsyncCall(String),
    HttpRequestParsing(String),
    HttpResponseParsing(String),
    HttpMethodParsing(String),
    Parse(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::OID4VPHolder(s) => write!(f, "OID4VP Holder service error: {s}"),
            Error::DIDResolution { details } => write!(f, "DID resolution error: {details}"),
            Error::OID4VCIInternal(s) => write!(f, "OID4VCI Internal error: {s}"),
            Error::OID4VCIProtocol {
                error,
                error_description,
                ..
            } => {
                write!(
                    f,
                    "OID4VCI Internal error: {:?} {}",
                    error,
                    error_description.as_deref().unwrap_or("")
                )
            }
            Error::DIDResolver(s) => write!(f, "DID Resolver error: {s}"),
            Error::Vault(s) => write!(f, "Vault error: {s}"),
            Error::Kms(s) => write!(f, "Kms error: {s}"),
            Error::KeyHandle(s) => write!(f, "KeyHandle error: {s}"),
            Error::HttpAsyncCall(s) => write!(f, "Http async call error: {s}"),
            Error::HttpRequestParsing(s) => write!(f, "Http Request parsing error: {s}"),
            Error::HttpResponseParsing(s) => write!(f, "Http Response parsing error: {s}"),
            Error::HttpMethodParsing(s) => write!(f, "Http method parsing error: {s}"),
            Error::Parse(s) => write!(f, "Error during parsing: {s}"),
        }
    }
}
pub type JsonValue = serde_json::Value;

uniffi::custom_type!(JsonValue, String, {
    remote,
    lower: |val: &JsonValue| -> String {
        serde_json::to_string(&val)
            .unwrap_or_else(|_| String::from("null"))
    },
    try_lift: |val: String| -> JsonValue {
        Ok(serde_json::from_str(&val)?)
    }
});

pub type Duration = time::Duration;

uniffi::custom_type!(Duration, i64, {
    remote,
    lower: |val: &Duration| val.whole_seconds(),
    try_lift: |seconds: i64| Ok(Duration::seconds(seconds))
});

pub type OffsetDateTime = time::OffsetDateTime;

uniffi::custom_type!(OffsetDateTime, i64, {
    remote,
    lower: |val: &OffsetDateTime| val.unix_timestamp(),
    try_lift: |seconds: i64| Ok(OffsetDateTime::from_unix_timestamp(seconds)?)
});

pub fn deserialize_space_delimited_vec<'de, T, D>(
    deserializer: D,
) -> std::result::Result<T, D::Error>
where
    T: Default + Deserialize<'de>,
    D: Deserializer<'de>,
{
    if let Some(space_delimited) = Option::<String>::deserialize(deserializer)? {
        let entries = space_delimited
            .split(' ')
            .map(|s| serde_json::Value::String(s.to_string()))
            .collect();
        T::deserialize(serde_json::Value::Array(entries)).map_err(serde::de::Error::custom)
    } else {
        // If the JSON value is null, use the default value.
        Ok(T::default())
    }
}
