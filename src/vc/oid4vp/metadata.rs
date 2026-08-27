use crate::vc::oid4vp::ClientMetadata;
use openid4vp::core::credential_format::ClaimFormatPayload;
use openid4vp::core::metadata::WalletMetadata;
use openid4vp::core::metadata::parameters::VpFormatsSupported;
use openid4vp::core::object::UntypedObject;
use serde_json::Value;
use tracing::{Level, instrument};

type Level_ = Level;

//These metadata below are used in production. Change carefully.
// https://openid.net/specs/openid-4-verifiable-presentations-1_0-29.html#name-metadata-4
const DEFAULT_CLIENT_METADATA: &str = r#"{
    "vp_formats_supported": {
        "dc+sd-jwt": {
            "sd-jwt_alg_values": ["EdDSA", "ES256"],
            "kb-jwt_alg_values": ["EdDSA", "ES256"]
        },
        "mso_mdoc": {
            "issuerauth_alg_values": [-8, -7],
            "deviceauth_alg_values": [-8, -7]
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
    get_vp_formats(DEFAULT_CLIENT_METADATA)
}

const VERIFIABLE_VP_FORMATS: &str = r#"{
    "vp_formats_supported": {
        "dc+sd-jwt": {
            "sd-jwt_alg_values": ["EdDSA", "ES256"],
            "kb-jwt_alg_values": ["EdDSA", "ES256"]
        },
        "mso_mdoc": {
            "issuerauth_alg_values": [-7, -8],
            "deviceauth_alg_values": [-7, -8]
        },
        "ldp_vc": {}
    }
}"#;

fn get_vp_formats(client_metadata: &str) -> VpFormatsSupported {
    ClientMetadata::try_from(serde_json::from_str::<Value>(client_metadata).unwrap())
        .unwrap()
        .0
        .get::<VpFormatsSupported>()
        .unwrap()
        .unwrap()
}

pub fn ensure_supported_vp_formats(metadata: &ClientMetadata) -> Result<(), String> {
    let unsupported = unsupported_vp_formats(metadata);

    if unsupported.is_empty() {
        return Ok(());
    }

    Err(unsupported.join(", "))
}

pub fn unsupported_vp_formats(metadata: &ClientMetadata) -> Vec<String> {
    let requested = match metadata.0.get::<VpFormatsSupported>() {
        None => return Vec::new(),
        Some(Err(e)) => return vec![format!("vp_formats_supported cannot be parsed: {e}")],
        Some(Ok(requested)) => requested,
    };
    let supported = get_vp_formats(VERIFIABLE_VP_FORMATS);

    let mut unsupported = Vec::new();
    for (designation, payload) in requested.0.iter() {
        let Some(supported_payload) = supported.0.get(designation) else {
            unsupported.push(designation.to_string());
            continue;
        };

        unsupported.extend(
            unsupported_algorithms(payload, supported_payload)
                .into_iter()
                .map(|algorithm| format!("{designation}: {algorithm}")),
        );
    }

    unsupported
}

fn unsupported_algorithms(
    requested: &ClaimFormatPayload,
    supported: &ClaimFormatPayload,
) -> Vec<String> {
    match (requested, supported) {
        (_, ClaimFormatPayload::Json(Value::Object(supported))) if supported.is_empty() => {
            Vec::new()
        }
        (ClaimFormatPayload::Alg(requested), ClaimFormatPayload::Alg(supported))
        | (
            ClaimFormatPayload::AlgValuesSupported(requested),
            ClaimFormatPayload::AlgValuesSupported(supported),
        )
        | (ClaimFormatPayload::ProofType(requested), ClaimFormatPayload::ProofType(supported)) => {
            missing_values(requested, supported)
        }
        (
            ClaimFormatPayload::SdJwtAlgValues {
                sd_jwt_alg_values: requested_sd_jwt,
                kb_jwt_alg_values: requested_kb_jwt,
            },
            ClaimFormatPayload::SdJwtAlgValues {
                sd_jwt_alg_values: supported_sd_jwt,
                kb_jwt_alg_values: supported_kb_jwt,
            },
        ) => {
            let mut missing = missing_values(requested_sd_jwt, supported_sd_jwt);
            missing.extend(missing_values(requested_kb_jwt, supported_kb_jwt));
            missing
        }
        (ClaimFormatPayload::Json(requested), ClaimFormatPayload::Json(supported)) => {
            missing_json_values(requested, supported)
        }
        _ => Vec::new(),
    }
}

/// The entries of `requested` absent from `supported`, for the flat string
/// algorithm lists (`["EdDSA", "ES256"]`).
fn missing_values(requested: &[String], supported: &[String]) -> Vec<String> {
    requested
        .iter()
        .filter(|value| !supported.contains(*value))
        .cloned()
        .collect()
}

/// The same comparison as [`missing_values`] for a format the upstream crate
/// models as raw JSON rather than a typed payload, i.e. `mso_mdoc`: an object of
/// named algorithm arrays (`issuerauth_alg_values`, `deviceauth_alg_values`),
/// whose values are COSE algorithm numbers rather than JOSE names. Each hit is
/// labelled with the property it came from.
///
/// A property `supported` does not mention, or either side holding a non-array,
/// is skipped rather than reported — an unrecognized shape is not evidence of an
/// algorithm the SDK cannot handle.
fn missing_json_values(requested: &Value, supported: &Value) -> Vec<String> {
    let (Some(requested), Some(supported)) = (requested.as_object(), supported.as_object()) else {
        return Vec::new();
    };

    requested
        .iter()
        .filter_map(|(property, values)| {
            let values = values.as_array()?;
            let supported = supported.get(property)?.as_array()?;

            Some(
                values
                    .iter()
                    .filter(|value| !supported.contains(*value))
                    .map(|value| format!("{property}: {value}"))
                    .collect::<Vec<_>>(),
            )
        })
        .flatten()
        .collect()
}

/// The Wallet issuer identifier OID4VP 1.0 §5.8 assigns to Static Discovery, and the `aud` of a
/// signed Request Object addressed to a Wallet whose metadata was not discovered dynamically.
pub(crate) const SELF_ISSUED_V2: &str = "https://self-issued.me/v2";

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
        "redirect_uri",
        "x509_san_dns",
        "x509_hash"
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
    use crate::vc::oid4vp::ClientMetadata;
    use crate::vc::oid4vp::metadata::{
        default_client_metadata, default_vp_formats, default_wallet_metadata,
        ensure_supported_vp_formats, unsupported_vp_formats,
    };

    fn client_metadata(json: &str) -> ClientMetadata {
        ClientMetadata::try_from(serde_json::from_str::<serde_json::Value>(json).unwrap()).unwrap()
    }

    #[test]
    fn default_metadata_creation_does_not_panic() {
        default_client_metadata();
        default_vp_formats();
        default_wallet_metadata();
    }

    #[test]
    fn the_default_metadata_advertises_nothing_it_cannot_honor() {
        assert!(unsupported_vp_formats(&default_client_metadata()).is_empty());
    }

    #[test]
    fn the_default_client_metadata_is_accepted_by_the_default_wallet_metadata() {
        let wallet = default_wallet_metadata();
        let honored = wallet.vp_formats_supported();

        assert!(
            default_vp_formats()
                .0
                .iter()
                .any(|(designation, payload)| honored
                    .contains_claim_format_with_payload(designation, payload)),
            "the default wallet metadata honors none of the formats the default client metadata \
             advertises"
        );
    }

    #[test]
    fn metadata_without_vp_formats_is_accepted() {
        assert!(
            unsupported_vp_formats(&client_metadata(r#"{"client_name": "Verifier"}"#)).is_empty()
        );
    }

    #[test]
    fn a_format_the_sdk_cannot_verify_is_reported() {
        let metadata = client_metadata(
            r#"{"vp_formats_supported": {"jwt_vc_json": {"alg_values_supported": ["ES256"]}}}"#,
        );

        // Named by its wire designation, not by the upstream Rust variant: the
        // consumer reading this reported the format as `jwt_vc_json`.
        assert_eq!(unsupported_vp_formats(&metadata), vec!["jwt_vc_json"]);
    }

    #[test]
    fn vp_formats_that_cannot_be_parsed_are_reported_rather_than_accepted() {
        let metadata = client_metadata(r#"{"vp_formats_supported": "not an object"}"#);

        assert_eq!(unsupported_vp_formats(&metadata).len(), 1);
        assert!(ensure_supported_vp_formats(&metadata).is_err());
    }

    #[test]
    fn any_ldp_vc_proof_type_is_accepted() {
        let metadata = client_metadata(
            r#"{"vp_formats_supported": {"ldp_vc": {"proof_type": [
                "Ed25519Signature2018",
                "EcdsaSecp256k1Signature2019"
            ]}}}"#,
        );

        assert!(unsupported_vp_formats(&metadata).is_empty());
    }

    #[test]
    fn an_sd_jwt_algorithm_the_default_does_not_carry_is_reported() {
        let metadata = client_metadata(
            r#"{"vp_formats_supported": {"dc+sd-jwt": {
                "sd-jwt_alg_values": ["ES256", "RS256"],
                "kb-jwt_alg_values": ["ES256"]
            }}}"#,
        );

        let unsupported = unsupported_vp_formats(&metadata);

        assert_eq!(unsupported.len(), 1);
        assert!(unsupported[0].contains("RS256"));
    }

    #[test]
    fn an_mdoc_algorithm_the_default_does_not_carry_is_reported() {
        // `mso_mdoc` has no typed payload variant, so this also covers the raw-JSON comparison.
        let metadata = client_metadata(
            r#"{"vp_formats_supported": {"mso_mdoc": {
                "issuerauth_alg_values": [-7, -35],
                "deviceauth_alg_values": [-7]
            }}}"#,
        );

        let unsupported = unsupported_vp_formats(&metadata);

        assert_eq!(unsupported.len(), 1);
        assert!(unsupported[0].contains("-35"));
    }

    #[test]
    fn a_narrower_advertisement_than_the_default_is_accepted() {
        let metadata = client_metadata(
            r#"{"vp_formats_supported": {"dc+sd-jwt": {
                "sd-jwt_alg_values": ["ES256"],
                "kb-jwt_alg_values": ["ES256"]
            }}}"#,
        );

        assert!(unsupported_vp_formats(&metadata).is_empty());
    }
}
