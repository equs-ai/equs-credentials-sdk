use crate::did::ResolutionError;
use crate::did::didethr::types::did_events::{DidAttributeChanged, DidEvents};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::str::from_utf8;

#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
pub enum VerificationKeyType {
    #[default]
    EcdsaSecp256k1RecoveryMethod2020,
    Ed25519VerificationKey2018,
    RsaVerificationKey2018,
    X25519KeyAgreementKey2019,
    EcdsaSecp256k1VerificationKey2019,
    Secp256k1VerificationKey2018,
    JsonWebKey2020,
    EcdsaSecp256k1VerificationKey2020,
    Ed25519VerificationKey2020,
    X25519KeyAgreementKey2020,
}

impl AsRef<str> for VerificationKeyType {
    fn as_ref(&self) -> &str {
        match self {
            Self::EcdsaSecp256k1RecoveryMethod2020 => "EcdsaSecp256k1RecoveryMethod2020",
            Self::Ed25519VerificationKey2018 => "Ed25519VerificationKey2018",
            Self::RsaVerificationKey2018 => "RsaVerificationKey2018",
            Self::X25519KeyAgreementKey2019 => "X25519KeyAgreementKey2019",
            Self::EcdsaSecp256k1VerificationKey2019 => "EcdsaSecp256k1VerificationKey2019",
            Self::Secp256k1VerificationKey2018 => "Secp256k1VerificationKey2018",
            Self::JsonWebKey2020 => "JsonWebKey2020",
            Self::EcdsaSecp256k1VerificationKey2020 => "EcdsaSecp256k1VerificationKey2020",
            Self::Ed25519VerificationKey2020 => "Ed25519VerificationKey2020",
            Self::X25519KeyAgreementKey2020 => "X25519KeyAgreementKey2020",
        }
    }
}

impl std::fmt::Display for VerificationKeyType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyAttribute {
    pub purpose: PublicKeyPurpose,
    #[serde(rename = "type")]
    pub type_: PublicKeyType,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_base58: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_pem: Option<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub enum PublicKeyPurpose {
    #[default]
    #[serde(rename = "veriKey")]
    VeriKey,
    #[serde(rename = "sigAuth")]
    SigAuth,
    #[serde(rename = "enc")]
    Enc,
}

impl AsRef<str> for PublicKeyPurpose {
    fn as_ref(&self) -> &str {
        match self {
            PublicKeyPurpose::VeriKey => "veriKey",
            PublicKeyPurpose::SigAuth => "sigAuth",
            PublicKeyPurpose::Enc => "enc",
        }
    }
}

impl TryFrom<&str> for PublicKeyPurpose {
    type Error = ResolutionError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "veriKey" => Ok(PublicKeyPurpose::VeriKey),
            "sigAuth" => Ok(PublicKeyPurpose::SigAuth),
            "enc" => Ok(PublicKeyPurpose::Enc),
            value => Err(ResolutionError::Internal(format!(
                "Unexpected public key purpose {}",
                value
            ))),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub enum DelegateType {
    #[default]
    #[serde(rename = "veriKey")]
    VeriKey,
    #[serde(rename = "sigAuth")]
    SigAuth,
}

impl AsRef<str> for DelegateType {
    fn as_ref(&self) -> &str {
        match self {
            DelegateType::VeriKey => "veriKey",
            DelegateType::SigAuth => "sigAuth",
        }
    }
}

impl TryFrom<&str> for DelegateType {
    type Error = ResolutionError;
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "veriKey" => Ok(DelegateType::VeriKey),
            "sigAuth" => Ok(DelegateType::SigAuth),
            value => Err(ResolutionError::Internal(format!(
                "Unexpected public key delegate type {}",
                value
            ))),
        }
    }
}

impl TryFrom<&[u8]> for DelegateType {
    type Error = ResolutionError;
    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        let str = crate::did::didethr::utils::parse_bytes32_string(value)?;
        Self::try_from(str)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Deserialize, Serialize)]
pub enum PublicKeyType {
    #[default]
    Ed25519VerificationKey2020,
    X25519KeyAgreementKey2020,
    EcdsaSecp256k1VerificationKey2020,
}

impl PublicKeyType {
    pub fn to_name(&self) -> &str {
        match self {
            PublicKeyType::EcdsaSecp256k1VerificationKey2020 => "Secp256k1",
            PublicKeyType::Ed25519VerificationKey2020 => "Ed25519",
            PublicKeyType::X25519KeyAgreementKey2020 => "X25519",
        }
    }

    pub fn from_name(name: &str) -> Result<Self, ResolutionError> {
        match name {
            "Secp256k1" => Ok(PublicKeyType::EcdsaSecp256k1VerificationKey2020),
            "Ed25519" => Ok(PublicKeyType::Ed25519VerificationKey2020),
            "X25519" => Ok(PublicKeyType::X25519KeyAgreementKey2020),
            value => Err(ResolutionError::Internal(format!(
                "Unexpected public key type {}",
                value
            ))),
        }
    }
}

impl From<PublicKeyType> for VerificationKeyType {
    fn from(value: PublicKeyType) -> Self {
        match value {
            PublicKeyType::EcdsaSecp256k1VerificationKey2020 => {
                VerificationKeyType::EcdsaSecp256k1VerificationKey2020
            }
            PublicKeyType::Ed25519VerificationKey2020 => {
                VerificationKeyType::Ed25519VerificationKey2020
            }
            PublicKeyType::X25519KeyAgreementKey2020 => {
                VerificationKeyType::X25519KeyAgreementKey2020
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAttribute {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: String,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum DidDocAttribute {
    PublicKey(PublicKeyAttribute),
    Service(ServiceAttribute),
}

impl TryFrom<DidEvents> for DidDocAttribute {
    type Error = ResolutionError;
    fn try_from(value: DidEvents) -> Result<Self, Self::Error> {
        match value {
            DidEvents::AttributeChangedEvent(event) => DidDocAttribute::try_from(event),
            _ => Err(ResolutionError::Internal(
                "Unable to get DidDocAttribute from event.".to_string(),
            )),
        }
    }
}

impl TryFrom<DidAttributeChanged> for DidDocAttribute {
    type Error = ResolutionError;
    fn try_from(event: DidAttributeChanged) -> Result<Self, Self::Error> {
        let parts = event.name.split('/').collect::<Vec<&str>>();
        let kind = parts.get(1).ok_or_else(|| {
            ResolutionError::Internal(
                "Unable to convert DIDAttributeChangedEvent into DidDocAttribute".to_string(),
            )
        })?;

        match kind.to_owned() {
            "pub" => {
                let type_ = parts.get(2).ok_or_else(|| ResolutionError::Internal(format!("Unable to convert DIDAttributeChangedEvent into public key DidDocAttribute. `type` not found {}", event.name)))?;
                let purpose = parts.get(3).ok_or_else(|| ResolutionError::Internal(format!("Unable to convert DIDAttributeChangedEvent into public key DidDocAttribute. `purpose` not found {}", event.name)))?;
                let encoding = parts.get(4).ok_or_else(|| ResolutionError::Internal(format!("Unable to convert DIDAttributeChangedEvent into public key DidDocAttribute. `encoding` not found {}", event.name)))?;

                let mut public_key = PublicKeyAttribute {
                    purpose: PublicKeyPurpose::try_from(*purpose)?,
                    type_: PublicKeyType::from_name(type_)?,
                    public_key_hex: None,
                    public_key_base64: None,
                    public_key_base58: None,
                    public_key_pem: None,
                };

                match encoding.to_owned() {
                    "base58" => {
                        public_key.public_key_base58 =
                            Some(bs58::encode(&event.value).into_string());
                    }
                    "hex" => {
                        public_key.public_key_hex = Some(hex::encode(&event.value));
                    }
                    "base64" => {
                        public_key.public_key_base64 = Some(
                            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&event.value),
                        );
                    }
                    value => {
                        return Err(ResolutionError::Internal(format!(
                            "Unable to convert DIDAttributeChangedEvent into public key DidDocAttribute. `encoding` not found {}",
                            value
                        )));
                    }
                }

                Ok(DidDocAttribute::PublicKey(public_key))
            }
            "svc" => {
                let type_ = parts.get(2).ok_or_else(|| ResolutionError::Internal(format!("Unable to convert DIDAttributeChangedEvent into service DidDocAttribute. `type` not found {}", event.name)))?;
                let value = from_utf8(&event.value).map_err(|err| ResolutionError::Internal(format!("Unable to convert DIDAttributeChangedEvent into service DidDocAttribute. Failed to parse value: {}", err)))?;
                let service_endpoint = if value.starts_with('{') {
                    serde_json::from_slice::<serde_json::Value>(&event.value).map_err(|err| ResolutionError::Internal(format!("Unable to convert DIDAttributeChangedEvent into service DidDocAttribute. Failed to parse value: {}", err)))?.to_string()
                } else {
                    value.to_string()
                };

                Ok(DidDocAttribute::Service(ServiceAttribute {
                    type_: type_.to_string(),
                    service_endpoint,
                }))
            }
            val => Err(ResolutionError::Internal(format!(
                "Unable to convert DIDAttributeChangedEvent into DidDocAttribute. Unknown kind: {}",
                val
            ))),
        }
    }
}
