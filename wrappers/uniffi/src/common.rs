pub type Result<T> = std::result::Result<T, Error>;

#[derive(uniffi::Error, Debug)]
pub enum Error {
    OID4VPHolder(String),
    DIDResolution { details: String },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::OID4VPHolder(s) => write!(f, "OID4VP Holder service error: {s}"),
            Error::DIDResolution { details } => write!(f, "DID resolution error: {details}"),
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
