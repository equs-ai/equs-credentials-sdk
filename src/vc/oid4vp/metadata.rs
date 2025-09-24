use crate::vc::oid4vp::ClientMetadata;
use openid4vp::core::metadata::WalletMetadata;
use openid4vp::core::metadata::parameters::VpFormatsSupported;
use openid4vp::core::object::UntypedObject;
use tracing::{Level, instrument};

type Level_ = Level;

//These metadata below are used in production. Change carefully.
// https://openid.net/specs/openid-4-verifiable-presentations-1_0-29.html#name-metadata-4
const DEFAULT_CLIENT_METADATA: &str = r#"{
    "vp_formats_supported": {
        "dc+sd-jwt": {
            "sd-jwt_alg_values": ["EdDSA", "ES256"],
            "kb-jwt_alg_values": ["EdDSA", "ES256"]
        }
    }
}"#;

#[instrument(
    level = Level::TRACE,
    ret(),
)]
pub fn default_client_metadata() -> ClientMetadata {
    ClientMetadata::try_from(
        serde_json::from_str::<serde_json::Value>(DEFAULT_CLIENT_METADATA).unwrap(),
    )
    .unwrap()
}

#[instrument(
    level = Level::TRACE,
    ret(),
)]
pub fn default_vp_formats() -> VpFormatsSupported {
    default_client_metadata()
        .0
        .get::<VpFormatsSupported>()
        .unwrap()
        .unwrap()
}

const DEFAULT_WALLET_METADATA: &str = r#"{
    "issuer": "https://self-issued.me/v2",
    "authorization_endpoint": "openid4vp://",
    "response_types_supported": [
        "vp_token",
        "vp_token id_token"
    ],
    "vp_formats_supported":
    {
        "dc+sd-jwt": {
            "sd-jwt_alg_values": ["EdDSA", "ES256"],
            "kb-jwt_alg_values": ["EdDSA", "ES256"]
        },
        "ldp_vc": {
           "proof_type": [
            "Ed25519Signature2018",
            "EcdsaSecp256k1Signature2019",
            "EcdsaRdfc2019",
            "EdDsaRdfc2022"
           ]
        }
    },
    "client_id_prefixes_supported": [
        "decentralized_identifier",
        "redirect_uri"
    ],
    "request_object_signing_alg_values_supported": [
        "EdDSA",
        "ES256"
    ],
    "subject_syntax_types_supported": [
        "did:key"
    ],
    "id_token_types_supported": [
        "subject_signed_id_token"
    ]
}"#;

#[instrument(
    level = Level::TRACE,
    ret(),
)]
pub fn default_wallet_metadata() -> WalletMetadata {
    WalletMetadata::try_from(
        serde_json::from_str::<UntypedObject>(DEFAULT_WALLET_METADATA).unwrap(),
    )
    .unwrap()
}

#[cfg(test)]
mod test {
    use crate::vc::oid4vp::metadata::{
        default_client_metadata, default_vp_formats, default_wallet_metadata,
    };

    #[test]
    fn default_metadata_creation_does_not_panic() {
        default_client_metadata();
        default_vp_formats();
        default_wallet_metadata();
    }
}
