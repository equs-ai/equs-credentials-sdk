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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::did::didethr::types::Address;
    use crate::did::didethr::types::Block;
    use rstest::rstest;

    fn attr(name: &str, value: Vec<u8>) -> DidAttributeChanged {
        DidAttributeChanged {
            identity: Address::from("0x1111111111111111111111111111111111111111"),
            name: name.to_string(),
            value,
            valid_to: 0,
            previous_change: Block::from(0),
        }
    }

    #[rstest]
    #[case::veri_key("veriKey", PublicKeyPurpose::VeriKey)]
    #[case::sig_auth("sigAuth", PublicKeyPurpose::SigAuth)]
    #[case::enc("enc", PublicKeyPurpose::Enc)]
    fn public_key_purpose_try_from_str_accepts_known_variants(
        #[case] input: &str,
        #[case] expected: PublicKeyPurpose,
    ) {
        assert_eq!(PublicKeyPurpose::try_from(input).unwrap(), expected);
    }

    #[test]
    #[should_panic(expected = "Unexpected public key purpose")]
    fn public_key_purpose_try_from_str_rejects_unknown_variant() {
        PublicKeyPurpose::try_from("unknown").unwrap();
    }

    #[rstest]
    #[case::veri_key("veriKey", DelegateType::VeriKey)]
    #[case::sig_auth("sigAuth", DelegateType::SigAuth)]
    fn delegate_type_try_from_str_accepts_known_variants(
        #[case] input: &str,
        #[case] expected: DelegateType,
    ) {
        assert_eq!(DelegateType::try_from(input).unwrap(), expected);
    }

    #[test]
    #[should_panic(expected = "Unexpected public key delegate type")]
    fn delegate_type_try_from_str_rejects_unknown_variant() {
        DelegateType::try_from("enc").unwrap();
    }

    #[test]
    fn delegate_type_try_from_bytes32_decodes_padded_utf8_label() {
        // bytes32 form: "veriKey" + zero-padding to 32 bytes.
        let mut bytes = [0u8; 32];
        bytes[..b"veriKey".len()].copy_from_slice(b"veriKey");

        assert_eq!(
            DelegateType::try_from(&bytes[..]).unwrap(),
            DelegateType::VeriKey
        );
    }

    #[test]
    fn delegate_type_try_from_bytes32_decodes_sig_auth() {
        let mut bytes = [0u8; 32];
        bytes[..b"sigAuth".len()].copy_from_slice(b"sigAuth");

        assert_eq!(
            DelegateType::try_from(&bytes[..]).unwrap(),
            DelegateType::SigAuth
        );
    }

    #[test]
    #[should_panic(expected = "Unexpected public key delegate type")]
    fn delegate_type_try_from_bytes32_rejects_unknown_label() {
        let mut bytes = [0u8; 32];
        bytes[..b"bogus".len()].copy_from_slice(b"bogus");

        DelegateType::try_from(&bytes[..]).unwrap();
    }

    #[rstest]
    #[case::secp256k1(PublicKeyType::EcdsaSecp256k1VerificationKey2020, "Secp256k1")]
    #[case::ed25519(PublicKeyType::Ed25519VerificationKey2020, "Ed25519")]
    #[case::x25519(PublicKeyType::X25519KeyAgreementKey2020, "X25519")]
    fn public_key_type_to_name_returns_short_label(
        #[case] kt: PublicKeyType,
        #[case] expected: &str,
    ) {
        assert_eq!(kt.to_name(), expected);
    }

    #[rstest]
    #[case::secp256k1("Secp256k1", PublicKeyType::EcdsaSecp256k1VerificationKey2020)]
    #[case::ed25519("Ed25519", PublicKeyType::Ed25519VerificationKey2020)]
    #[case::x25519("X25519", PublicKeyType::X25519KeyAgreementKey2020)]
    fn public_key_type_from_name_parses_known_labels(
        #[case] label: &str,
        #[case] expected: PublicKeyType,
    ) {
        assert_eq!(PublicKeyType::from_name(label).unwrap(), expected);
    }

    #[test]
    #[should_panic(expected = "Unexpected public key type")]
    fn public_key_type_from_name_rejects_unknown_label() {
        PublicKeyType::from_name("BLS12381").unwrap();
    }

    #[rstest]
    #[case::secp256k1(
        PublicKeyType::EcdsaSecp256k1VerificationKey2020,
        VerificationKeyType::EcdsaSecp256k1VerificationKey2020
    )]
    #[case::ed25519(
        PublicKeyType::Ed25519VerificationKey2020,
        VerificationKeyType::Ed25519VerificationKey2020
    )]
    #[case::x25519(
        PublicKeyType::X25519KeyAgreementKey2020,
        VerificationKeyType::X25519KeyAgreementKey2020
    )]
    fn from_public_key_type_for_verification_key_type_maps_each_variant(
        #[case] input: PublicKeyType,
        #[case] expected: VerificationKeyType,
    ) {
        assert_eq!(VerificationKeyType::from(input), expected);
    }

    #[test]
    fn did_doc_attribute_from_pub_hex_event_yields_hex_encoded_public_key() {
        let event = attr(
            "did/pub/Secp256k1/veriKey/hex",
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );

        let attribute = DidDocAttribute::try_from(event).unwrap();

        match attribute {
            DidDocAttribute::PublicKey(pk) => {
                assert_eq!(pk.purpose, PublicKeyPurpose::VeriKey);
                assert_eq!(pk.type_, PublicKeyType::EcdsaSecp256k1VerificationKey2020);
                assert_eq!(pk.public_key_hex.as_deref(), Some("deadbeef"));
                assert!(pk.public_key_base58.is_none());
                assert!(pk.public_key_base64.is_none());
            }
            other => panic!("expected PublicKey, got {other:?}"),
        }
    }

    #[test]
    fn did_doc_attribute_from_pub_base58_event_yields_base58_encoded_public_key() {
        let event = attr("did/pub/Ed25519/sigAuth/base58", vec![0x01, 0x02, 0x03]);

        let attribute = DidDocAttribute::try_from(event).unwrap();

        match attribute {
            DidDocAttribute::PublicKey(pk) => {
                assert_eq!(pk.purpose, PublicKeyPurpose::SigAuth);
                assert_eq!(pk.type_, PublicKeyType::Ed25519VerificationKey2020);
                assert_eq!(pk.public_key_base58.as_deref(), Some("Ldp"));
                assert!(pk.public_key_hex.is_none());
            }
            other => panic!("expected PublicKey, got {other:?}"),
        }
    }

    #[test]
    fn did_doc_attribute_from_pub_base64_event_yields_url_safe_no_pad_base64() {
        let event = attr("did/pub/X25519/enc/base64", vec![0xAA, 0xBB, 0xCC]);

        let attribute = DidDocAttribute::try_from(event).unwrap();

        match attribute {
            DidDocAttribute::PublicKey(pk) => {
                assert_eq!(pk.purpose, PublicKeyPurpose::Enc);
                assert_eq!(pk.type_, PublicKeyType::X25519KeyAgreementKey2020);
                // URL-safe-no-pad base64 of [0xAA, 0xBB, 0xCC] is "qrvM".
                assert_eq!(pk.public_key_base64.as_deref(), Some("qrvM"));
            }
            other => panic!("expected PublicKey, got {other:?}"),
        }
    }

    #[test]
    fn did_doc_attribute_from_svc_event_with_plain_endpoint_yields_service() {
        let event = attr("did/svc/LinkedDomains", b"https://example.com".to_vec());

        let attribute = DidDocAttribute::try_from(event).unwrap();

        match attribute {
            DidDocAttribute::Service(svc) => {
                assert_eq!(svc.type_, "LinkedDomains");
                assert_eq!(svc.service_endpoint, "https://example.com");
            }
            other => panic!("expected Service, got {other:?}"),
        }
    }

    #[test]
    fn did_doc_attribute_from_svc_event_with_json_endpoint_reserialises_value() {
        let event = attr("did/svc/Custom", br#"{"uri":"https://x.test"}"#.to_vec());

        let attribute = DidDocAttribute::try_from(event).unwrap();

        match attribute {
            DidDocAttribute::Service(svc) => {
                assert_eq!(svc.type_, "Custom");
                // JSON gets parsed and re-serialised; both forms are canonical
                // and identical here.
                assert_eq!(svc.service_endpoint, r#"{"uri":"https://x.test"}"#);
            }
            other => panic!("expected Service, got {other:?}"),
        }
    }

    #[test]
    #[should_panic(expected = "`encoding` not found")]
    fn did_doc_attribute_try_from_rejects_pub_event_missing_encoding_segment() {
        let event = attr("did/pub/Secp256k1/veriKey", vec![1, 2, 3]);

        DidDocAttribute::try_from(event).unwrap();
    }

    #[test]
    #[should_panic(expected = "`encoding` not found")]
    fn did_doc_attribute_try_from_rejects_pub_event_with_unknown_encoding() {
        let event = attr("did/pub/Secp256k1/veriKey/multibase", vec![1, 2, 3]);

        DidDocAttribute::try_from(event).unwrap();
    }

    #[test]
    #[should_panic(expected = "Unknown kind")]
    fn did_doc_attribute_try_from_rejects_unknown_kind_segment() {
        let event = attr("did/other/Secp256k1/veriKey/hex", vec![1, 2, 3]);

        DidDocAttribute::try_from(event).unwrap();
    }

    #[test]
    #[should_panic(expected = "Unable to get DidDocAttribute from event")]
    fn did_doc_attribute_try_from_didevents_rejects_non_attribute_variants() {
        use crate::did::didethr::types::did_events::{DidEvents, DidOwnerChanged};

        let event = DidEvents::OwnerChanged(DidOwnerChanged {
            identity: Address::from("0x0000000000000000000000000000000000000001"),
            owner: Address::from("0x0000000000000000000000000000000000000002"),
            previous_change: Block::from(0),
        });

        DidDocAttribute::try_from(event).unwrap();
    }
}
