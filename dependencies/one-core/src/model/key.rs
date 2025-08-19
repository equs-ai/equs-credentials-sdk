use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kty", rename_all = "UPPERCASE")]
pub enum PublicKeyJwk {
    Ec(PublicKeyJwkEllipticData),
    Rsa(PublicKeyJwkRsaData),
    Okp(PublicKeyJwkEllipticData),
    #[serde(rename = "oct")]
    Oct(PublicKeyJwkOctData),
    Mlwe(PublicKeyJwkMlweData),
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyJwkRsaData {
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub e: String,
    pub n: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyJwkOctData {
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub k: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyJwkMlweData {
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub alg: String,
    pub x: String,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKeyJwkEllipticData {
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
}

#[derive(Clone, Debug)]
pub enum PrivateKeyJwk {
    Ec(PrivateKeyJwkEllipticData),
    Okp(PrivateKeyJwkEllipticData),
    Mlwe(PrivateKeyJwkMlweData),
}

#[derive(Clone, Debug)]
pub struct PrivateKeyJwkMlweData {
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub alg: String,
    pub x: String,
    pub d: SecretString,
}

#[derive(Clone, Debug)]
pub struct PrivateKeyJwkEllipticData {
    pub r#use: Option<String>,
    pub kid: Option<String>,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
    pub d: SecretString,
}
