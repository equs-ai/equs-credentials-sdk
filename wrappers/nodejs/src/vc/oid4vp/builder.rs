use crate::did::JsDIDResolver;
use crate::http::ReqwestHttpClient;
use crate::kms::JsKms;
use crate::nonce::JsNonceHandler;
use crate::utils::from_json_object;
use crate::vault::JsVault;
use crate::vc::JsonObject;
use crate::vc::core::{JsKeyMetadata, JsProofOfPossessionMetadata};
use crate::vc::oid4vp::ClientId;
use crate::vc::oid4vp::holder::InnerOID4VPHolder;
use crate::vc::oid4vp::verifier::InternalOID4VPVerifier;
use equs_sdk::vc::core::KeyMetadata;
use equs_sdk::vc::oid4vp::ClientMetadata;
use equs_sdk::vc::trust::issuer::{CredentialClassification, IssuerTrustMode, RolelessAnchors};
use napi::bindgen_prelude::Uint8Array;
use napi::{Error, Result, Status};
use napi_derive::napi;

/// A certificate trusted to anchor credential issuers, e.g. one exported from a trust list.
#[napi(object, js_name = "TrustAnchor")]
pub struct JsTrustAnchor {
    /// PEM of the anchor certificate: a root, an intermediate CA or a listed signing certificate.
    pub pem: String,
    /// Opaque reference echoed in the issuer trust result (e.g. the source trust list).
    pub source_ref: Option<String>,
    /// Role the anchor is trusted for (e.g. `pid_provider`), echoed in the result.
    #[napi(
        ts_type = "'pid_provider' | 'qeaa_provider' | 'pub_eaa_provider' | 'eaa_provider' | 'wallet_provider' | 'wrp_ac_provider' | 'wrp_rc_provider' | 'registrar' | (string & {}) | undefined"
    )]
    pub role: Option<String>,
    /// Type of the granting trust-list service. Only issuing services, or no type, anchor issuers;
    /// other anchors only check status lists.
    pub service_type: Option<String>,
}

/// Credential types (`vct`, docType) classified as PIDs, QEAAs and PuB-EAAs, in addition to the
/// EUDI PID types. A trailing `*` matches by prefix. Unlisted credentials fall back to their
/// `category` claim (`urn:etsi:esi:eaa:eu:qualified`, `urn:etsi:esi:eaa:eu:pub`), then to EAA.
#[napi(object, js_name = "CredentialClassification")]
pub struct JsCredentialClassification {
    pub pid: Option<Vec<String>>,
    pub qeaa: Option<Vec<String>>,
    pub pub_eaa: Option<Vec<String>>,
}

impl From<JsCredentialClassification> for CredentialClassification {
    fn from(value: JsCredentialClassification) -> Self {
        Self {
            pid: value.pid.unwrap_or_default(),
            qeaa: value.qeaa.unwrap_or_default(),
            pub_eaa: value.pub_eaa.unwrap_or_default(),
        }
    }
}

fn parse_roleless_anchors(scope: &str) -> Result<RolelessAnchors> {
    serde_json::from_value(serde_json::Value::String(scope.to_string())).map_err(|_| {
        Error::new(
            Status::InvalidArg,
            format!(
                "unknown role-less anchor scope `{scope}`, expected `all_categories` or `eaa_only`"
            ),
        )
    })
}

fn parse_issuer_trust_mode(mode: &str) -> Result<IssuerTrustMode> {
    serde_json::from_value(serde_json::Value::String(mode.to_string())).map_err(|_| {
        Error::new(
            Status::InvalidArg,
            format!("unknown issuer trust mode `{mode}`, expected `enforce` or `report`"),
        )
    })
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub async fn _build_vp_verifier(
    kms: JsKms,
    nonce_generator: JsNonceHandler,
    key_metadata: JsKeyMetadata,
    client_id: &ClientId,
    #[napi(ts_arg_type = "ClientMetadata | null | undefined")] client_metadata: Option<JsonObject>,
    http_client: Option<&ReqwestHttpClient>,
    did_resolver: Option<JsDIDResolver>,
    trusted_root_certificates: Option<Vec<Uint8Array>>,
    x509_certificate_chain: Option<Uint8Array>,
    trust_anchors: Option<Vec<JsTrustAnchor>>,
    #[napi(ts_arg_type = "'enforce' | 'report' | null | undefined")] issuer_trust_mode: Option<
        String,
    >,
    credential_classification: Option<JsCredentialClassification>,
    #[napi(ts_arg_type = "'all_categories' | 'eaa_only' | null | undefined")]
    roleless_anchors: Option<String>,
) -> Result<InternalOID4VPVerifier> {
    let key_metadata: KeyMetadata = key_metadata.into();
    let mut builder = equs_sdk::vc::oid4vp::VerifierBuilder::new(
        kms,
        nonce_generator,
        key_metadata,
        client_id.0.clone(),
    );

    if let Some(client_metadata) = &client_metadata {
        builder = builder.with_client_metadata(
            ClientMetadata::try_from(from_json_object::<serde_json::Value>(
                client_metadata.clone(),
            )?)
            .map_err(|err| Error::new(Status::InvalidArg, err))?,
        );
    }
    if let Some(did_resolver) = did_resolver {
        builder = builder.with_did_resolver(did_resolver).unwrap();
    }

    if let Some(http_client) = http_client {
        builder = builder.with_http_client(http_client.inner())
    }

    if let Some(trusted_root_certificates) = trusted_root_certificates {
        for cert in trusted_root_certificates {
            builder = builder
                .add_trusted_root_certificate(&cert)
                .map_err(|err| Error::new(Status::InvalidArg, err))?;
        }
    }

    if let Some(x509_certificate_chain) = x509_certificate_chain {
        builder = builder
            .with_x509_certificate_chain(&x509_certificate_chain)
            .map_err(|err| Error::new(Status::InvalidArg, err))?;
    }

    // trusted roots first, then trust anchors
    for anchor in trust_anchors.unwrap_or_default() {
        builder = builder
            .add_trust_anchor(
                anchor.pem.as_bytes(),
                anchor.source_ref,
                anchor.role,
                anchor.service_type,
            )
            .map_err(|err| Error::new(Status::InvalidArg, err))?;
    }

    if let Some(mode) = issuer_trust_mode {
        builder = builder.with_issuer_trust_mode(parse_issuer_trust_mode(&mode)?);
    }
    if let Some(classification) = credential_classification {
        builder = builder.with_credential_classification(classification.into());
    }
    if let Some(scope) = roleless_anchors {
        builder = builder.with_roleless_anchors(parse_roleless_anchors(&scope)?);
    }

    let verifier = builder
        .build()
        .await
        .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

    Ok(InternalOID4VPVerifier::from_verifier(verifier))
}

#[napi]
#[allow(clippy::too_many_arguments)]
pub async fn _build_vp_holder(
    kms: JsKms,
    vault: JsVault,
    client_id: String,
    #[napi(ts_arg_type = "WalletMetadata | null | undefined")] wallet_metadata: Option<JsonObject>,
    http_client: &ReqwestHttpClient,
    pop: Option<JsProofOfPossessionMetadata>,
    did_resolver: Option<JsDIDResolver>,
    nonce_handler: Option<JsNonceHandler>,
) -> Result<InnerOID4VPHolder> {
    let mut builder =
        equs_sdk::vc::oid4vp::HolderBuilder::new(kms, vault, client_id, http_client.inner());

    if let Some(wallet_metadata) = &wallet_metadata {
        builder = builder.with_wallet_metadata(serde_json::from_value(from_json_object(
            wallet_metadata.clone(),
        )?)?)
    }

    if let Some(js_pop) = pop {
        builder = builder.with_pop(js_pop.try_into()?);
    }

    if let Some(did_resolver) = did_resolver {
        builder = builder.with_did_resolver(did_resolver).unwrap();
    }

    if let Some(nonce_handler) = nonce_handler {
        builder = builder.with_nonce_handler(Box::new(nonce_handler));
    }
    let holder = builder
        .build()
        .await
        .map_err(|err| Error::from_reason(format!("{:?}", err)))?;

    Ok(InnerOID4VPHolder::from_holder(holder))
}
