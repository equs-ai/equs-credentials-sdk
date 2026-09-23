//! Delegate SD-JWT (dSD-JWT) format primitives.
//! EXPERIMENTAL: tracks draft-gco-oauth-delegate-sd-jwt §3-6 via sd_jwt_rs.
//!
//! Gated behind the `delegate-sd-jwt` feature.
use std::collections::HashSet;

pub use sd_jwt_rs::ChainBindingMode;
use sd_jwt_rs::{SDJWTHolder, SDJWTSerializationFormat, SDJWTVerifier};
use serde_json::{Map, Value};
use tracing::{Level, instrument};

use crate::crypto::Signer;
use crate::did::universal::UniversalResolver;
use crate::vc::core::HolderBinder;
use crate::vc::formats::sd_jwt_vc::{Credential, DidKeyResolver, SignerWrapper};
use crate::vc::formats::{PresentationSnafu, Result, SigningSnafu, VerifyingSnafu};

#[derive(Debug, Default)]
pub struct DelegationParams {
    /// The delegate payload alternatives for this hop (one entry = single alternative).
    pub delegate_payloads: Vec<Value>,
    /// Claims from the original credential to forward (None = forward none / use default).
    pub claims_to_disclose: Option<Map<String, Value>>,
    /// Disclosure strings to drop from the wire (None = keep all).
    pub drop_disclosures: Option<HashSet<String>>,
    /// Chain binding mode. Callers may choose `SdHash` (crate default) or `IssuerJwtHash`.
    pub binding: ChainBindingMode,
    /// Audience to bind the grant to (the requesting Delegate Holder). When set, it is
    /// written into each delegate payload as the `aud` claim, which the Verifier checks
    /// against its expected audience (a plain dSD-JWT has no trailing KB-JWT, so the
    /// final KB-SD-JWT link's Delegate Payload carries the holder binding).
    pub aud: Option<String>,
    /// Request nonce to bind the grant to. When set, written into each delegate payload
    /// as the `nonce` claim and checked by the Verifier (see `aud`).
    pub nonce: Option<String>,
}

#[derive(Debug)]
pub struct DelegationChainView {
    pub verified_claims: Value,
    pub delegate_payloads: Vec<Vec<Map<String, Value>>>,
    pub chain_cnfs: Vec<jsonwebtoken::jwk::Jwk>,
}

#[derive(Debug)]
pub enum DsdJwtPurpose {
    Delegation(Option<HolderBinder>),
    Presentation(Option<HolderBinder>),
}

#[derive(Debug)]
pub struct DsdJwtAPI;

impl DsdJwtAPI {
    /// Append one delegation hop to an existing SD-JWT (or dSD-JWT) credential,
    /// returning a compact dSD-JWT string.
    ///
    /// The returned string ends with `~` (no trailing KB-JWT) — it is a *grant*
    /// (a credential to store / forward), not a verifiable presentation.
    ///
    /// # Arguments
    /// * `credential` — The SD-JWT (or dSD-JWT) to delegate from.
    /// * `holder_signer` — The current holder's signer (must match the `cnf` key
    ///   embedded in `credential`).
    /// * `params` — Delegation hop parameters.
    #[instrument(level = Level::TRACE, skip(holder_signer), err(), ret())]
    pub async fn create_delegated_credential<S: Signer>(
        credential: &Credential,
        holder_signer: S,
        params: DelegationParams,
    ) -> Result<Credential> {
        let sgn_wrapper = SignerWrapper {
            signer: holder_signer,
        };

        let mut holder = SDJWTHolder::new(credential.to_owned(), SDJWTSerializationFormat::Compact)
            .map_err(|err| {
                SigningSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        // Holder binding: write the request `aud`/`nonce` into each delegate payload.
        // For a plain dSD-JWT grant the final KB-SD-JWT link is the key binding, and the
        // crate verifies `aud`/`nonce` from that link's Delegate Payload.
        let mut delegate_payloads = params.delegate_payloads;
        if params.aud.is_some() || params.nonce.is_some() {
            for payload in &mut delegate_payloads {
                if let Some(obj) = payload.as_object_mut() {
                    if let Some(aud) = &params.aud {
                        obj.insert("aud".to_string(), Value::String(aud.clone()));
                    }
                    if let Some(nonce) = &params.nonce {
                        obj.insert("nonce".to_string(), Value::String(nonce.clone()));
                    }
                }
            }
        }

        holder
            .delegate(
                delegate_payloads,
                params.claims_to_disclose,
                params.drop_disclosures,
                sgn_wrapper,
                params.binding,
            )
            .await
            .map_err(|err| {
                PresentationSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }

    /// Verify a dSD-JWT chain, per `purpose`.
    ///
    /// # Arguments
    /// * `dsd_jwt` — The compact dSD-JWT string to verify.
    /// * `did_resolver` — DID resolver used to fetch the issuer's public key.
    /// * `purpose` — grant (no narrowing required) or final presentation; see
    ///   [`DsdJwtPurpose`].
    #[instrument(level = Level::TRACE, skip(did_resolver), err(), ret())]
    pub async fn verify_dsd_jwt(
        dsd_jwt: &Credential,
        did_resolver: UniversalResolver,
        purpose: DsdJwtPurpose,
    ) -> Result<DelegationChainView> {
        let mut verifier = SDJWTVerifier::new(Box::new(DidKeyResolver::new(did_resolver)));
        let (holder_binder, is_grant) = match purpose {
            DsdJwtPurpose::Delegation(hb) => (hb, true),
            DsdJwtPurpose::Presentation(hb) => (hb, false),
        };
        let (aud, nonce) = holder_binder
            .map(|hb| (Some(hb.verifier_id), Some(hb.nonce.secret().to_string())))
            .unwrap_or((None, None));

        let verified_claims = if is_grant {
            verifier
                .verify_delegation(
                    dsd_jwt.to_owned(),
                    aud,
                    nonce,
                    SDJWTSerializationFormat::Compact,
                )
                .await
                .map(Value::Object)
        } else {
            verifier
                .verify_presentation(
                    dsd_jwt.to_owned(),
                    aud,
                    nonce,
                    SDJWTSerializationFormat::Compact,
                )
                .await
        }
        .map_err(|err| {
            VerifyingSnafu {
                details: err.to_string(),
            }
            .build()
        })?;

        Ok(DelegationChainView {
            verified_claims,
            delegate_payloads: verifier.verified_delegate_payloads,
            chain_cnfs: verifier.chain_cnfs,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::Key;
    use crate::nonce::Nonce;
    use crate::vc::core::HolderBinder;
    use crate::vc::formats::sd_jwt_vc::VPMetadata;
    use crate::vc::formats::{API, VerifyOptions};

    use serde_json::{Map, json};

    use crate::did::universal::UniversalResolver;
    use crate::inmem::kms::LocalKms;
    use crate::kms::KeyType;
    use crate::utils::test_utils::create_did_url_and_key_handle;
    use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VCMetadata};

    use sd_jwt_rs::ChainBindingMode;

    use super::{DelegationParams, DsdJwtAPI, DsdJwtPurpose};

    /// Issue a holder-bound SD-JWT using our own `SdJwtAPI::create_vc` path.
    /// Returns `(sd_jwt_credential, holder_key_handle)` so that tests can immediately
    /// call `create_delegated_credential` without additional setup.
    async fn issue_sd_jwt() -> (String, impl crate::kms::KeyHandle + use<>) {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let claims = json!({
            "sub": "alice",
            "name": "Alice",
            "scope": "baseline",
        })
        .try_into()
        .unwrap();

        let metadata = VCMetadata {
            vct: "https://issuer.example/cred".to_owned(),
            lifetime: Some(time::Duration::days(365)),
            disclosures: vec![],
            credential_status: None,
        };

        let vc = SdJwtAPI::create_vc(
            claims,
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh.clone()),
            metadata,
            UniversalResolver::default(),
        )
        .await
        .unwrap();

        (vc, hld_kh)
    }

    /// A terminal grant (delegate payload has no `cnf`) should:
    /// - produce a dSD-JWT string ending with `~`
    /// - verify cleanly via `verify_dsd_jwt`
    /// - expose 1 delegate payload and an empty `chain_cnfs`
    /// - include a claim from the delegate payload in `verified_claims`
    #[tokio::test]
    async fn terminal_delegation_round_trips() {
        let (vc, hld_kh) = issue_sd_jwt().await;

        let dsd = DsdJwtAPI::create_delegated_credential(
            &vc,
            hld_kh,
            DelegationParams {
                delegate_payloads: vec![json!({
                    "scope": "purchase",
                    "merchant": "merchant.example",
                    "limit": 100,
                })],
                claims_to_disclose: Some(Map::new()),
                drop_disclosures: None,
                binding: ChainBindingMode::SdHash,
                ..Default::default()
            },
        )
        .await
        .expect("create_delegated_credential should succeed for a terminal grant");

        // A grant (no trailing KB-JWT) must end with `~`.
        assert!(
            dsd.ends_with('~'),
            "dSD-JWT grant must end with '~', got: {dsd}"
        );

        let view = DsdJwtAPI::verify_dsd_jwt(
            &dsd,
            UniversalResolver::default(),
            DsdJwtPurpose::Presentation(None),
        )
        .await
        .expect("verify_dsd_jwt should succeed");

        assert_eq!(
            view.delegate_payloads.len(),
            1,
            "expected exactly 1 delegate payload"
        );
        assert!(
            view.chain_cnfs.is_empty(),
            "terminal grant must have no chain_cnfs"
        );

        let claims = view
            .verified_claims
            .as_object()
            .expect("claims must be an object");
        assert_eq!(
            claims.get("scope"),
            Some(&serde_json::Value::String("purchase".into())),
            "delegate payload claim 'scope' must be visible in verified_claims"
        );
    }

    /// A delegate payload that carries a `cnf` JWK allows further re-delegation.
    /// After verification, `chain_cnfs` must have exactly one entry.
    ///
    /// We use the holder's own JWK as the delegate cnf (any P-256 JWK will do).
    #[tokio::test]
    async fn delegatable_grant_yields_one_cnf() {
        let (vc, hld_kh) = issue_sd_jwt().await;

        // Generate the delegate's JWK to embed in the cnf.
        let kms = LocalKms::new();
        let (_, delegate_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let delegate_jwk: ssi::jwk::JWK = delegate_kh.jwk().expect("delegate must have a JWK");
        // Convert to jsonwebtoken Jwk (the format sd_jwt_rs expects in cnf).
        let delegate_jwk_value =
            serde_json::to_value(&delegate_jwk).expect("ssi::jwk::JWK must serialize to JSON");

        let dsd = DsdJwtAPI::create_delegated_credential(
            &vc,
            hld_kh,
            DelegationParams {
                delegate_payloads: vec![json!({
                    "scope": "view-account",
                    "cnf": { "jwk": delegate_jwk_value },
                })],
                claims_to_disclose: Some(Map::new()),
                drop_disclosures: None,
                binding: ChainBindingMode::SdHash,
                ..Default::default()
            },
        )
        .await
        .expect("create_delegated_credential should succeed for a delegatable grant");

        let view = DsdJwtAPI::verify_dsd_jwt(
            &dsd,
            UniversalResolver::default(),
            DsdJwtPurpose::Presentation(None),
        )
        .await
        .expect("verify_dsd_jwt should succeed");

        assert_eq!(
            view.chain_cnfs.len(),
            1,
            "a cnf-carrying grant must yield chain_cnfs.len() == 1"
        );
        assert_eq!(view.delegate_payloads.len(), 1);
    }

    /// When `IssuerJwtHash` binding is used, the compact format must have an empty
    /// component immediately after the issuer JWT: `<issuer-jwt>~~<KB-SD-JWT>~...`.
    /// That is, splitting on `~` gives `parts[1].is_empty()`.
    #[tokio::test]
    async fn issuer_jwt_hash_binding_layout() {
        let (vc, hld_kh) = issue_sd_jwt().await;

        let dsd = DsdJwtAPI::create_delegated_credential(
            &vc,
            hld_kh,
            DelegationParams {
                delegate_payloads: vec![json!({ "purpose": "audit" })],
                claims_to_disclose: None,
                drop_disclosures: None,
                binding: ChainBindingMode::IssuerJwtHash,
                ..Default::default()
            },
        )
        .await
        .expect("create_delegated_credential should succeed with IssuerJwtHash");

        let parts: Vec<&str> = dsd.split('~').collect();
        assert!(
            parts
                .get(1)
                .unwrap_or_else(|| panic!("dSD-JWT has <2 '~' parts; got: {dsd:?}"))
                .is_empty(),
            "IssuerJwtHash layout must have an empty component after issuer JWT (got: {:?})",
            &parts[..parts.len().min(4)]
        );

        // Must also verify cleanly.
        let view = DsdJwtAPI::verify_dsd_jwt(
            &dsd,
            UniversalResolver::default(),
            DsdJwtPurpose::Presentation(None),
        )
        .await
        .expect("verify_dsd_jwt should succeed for IssuerJwtHash binding");

        assert_eq!(view.delegate_payloads.len(), 1);
        let claims = view.verified_claims.as_object().unwrap();
        assert_eq!(
            claims.get("purpose"),
            Some(&serde_json::Value::String("audit".into()))
        );
    }

    /// Full round-trip through the format layer:
    ///
    /// 1. Issue a holder-bound SD-JWT (via `SdJwtAPI::create_vc`).
    /// 2. Holder delegates to a Delegate Holder (embedding the delegate's cnf JWK),
    ///    producing a dSD-JWT grant.
    /// 3. Delegate Holder calls `SdJwtAPI::create_vp` to append a final KB-JWT
    ///    (signed by the delegate's own key).
    /// 4. Verifier calls `SdJwtAPI::verify_vp` with the matching nonce + aud.
    /// 5. Assertions: returned `Claims` includes both a delegate payload claim
    ///    (`scope = view-account`) AND an original issuer claim (`sub`).
    ///
    /// Expected: no production code change required — `create_vp` / `verify_vp`
    /// already delegate to `SDJWTHolder::create_presentation` /
    /// `SDJWTVerifier::verify_presentation` which are chain-aware.
    #[tokio::test]
    async fn delegate_holder_presents_dsd_jwt_kb_to_verifier() {
        // Step 1: Issue a holder-bound SD-JWT.
        let (vc, hld_kh) = issue_sd_jwt().await;

        // Step 2: Generate a delegate keypair and embed its public JWK in the
        // delegate payload so the delegate can sign a final KB-JWT.
        let kms = LocalKms::new();
        let (_, delegate_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let delegate_jwk: ssi::jwk::JWK = delegate_kh.jwk().expect("delegate must expose a JWK");
        let delegate_jwk_value =
            serde_json::to_value(&delegate_jwk).expect("ssi::jwk::JWK must serialize to JSON");

        // Holder delegates to the Delegate Holder, carrying `cnf` → this produces a
        // kb+sd-jwt+kb link that the delegate can present with a trailing KB-JWT.
        let dsd_jwt = DsdJwtAPI::create_delegated_credential(
            &vc,
            hld_kh,
            DelegationParams {
                delegate_payloads: vec![json!({
                    "scope": "view-account",
                    "cnf": { "jwk": delegate_jwk_value },
                })],
                claims_to_disclose: Some(Map::new()),
                drop_disclosures: None,
                binding: ChainBindingMode::SdHash,
                ..Default::default()
            },
        )
        .await
        .expect("create_delegated_credential should succeed");

        // Step 3: Delegate Holder presents the dSD-JWT with a trailing KB-JWT.
        let nonce = Nonce::from_secret("test-nonce-delegate-kb".to_string());
        let verifier_id = "verifier.example".to_string();

        let presentation = SdJwtAPI::create_vp(
            &dsd_jwt,
            delegate_kh,
            VPMetadata {
                disclosures: Map::new(),
                holder_binder: Some(HolderBinder {
                    nonce: nonce.clone(),
                    verifier_id: verifier_id.clone(),
                    response_uri: None,
                }),
            },
            UniversalResolver::default(),
        )
        .await
        .expect("create_vp on a dSD-JWT should append a trailing KB-JWT");

        // Step 4: Verifier verifies the full chain + KB-JWT.
        let verified_claims = SdJwtAPI::verify_vp(
            &presentation,
            Some(HolderBinder {
                nonce,
                verifier_id,
                response_uri: None,
            }),
            VerifyOptions::default(),
            UniversalResolver::default(),
        )
        .await
        .expect("verify_vp should validate the dSD-JWT chain and trailing KB-JWT");

        // Step 5: Assertions — both the delegate payload claim and an issuer claim
        // must be present in the returned Claims.
        use crate::vc::claims::Claim;
        assert_eq!(
            verified_claims.get("scope"),
            Some(&Claim::String("view-account".to_string())),
            "delegate payload claim 'scope' must be present in verified claims"
        );
        // `iss` is always revealed (not selectively disclosed), so it must always
        // appear in the verified claims even when no issuer disclosures are forwarded.
        assert!(
            verified_claims.get("iss").is_some(),
            "original issuer claim 'iss' must be present in verified claims"
        );
    }

    /// Purchase-bound delegation: the delegate payload injects `purchase_id`
    /// (a claim absent from the issued voucher). After the Delegate Holder presents
    /// with its own KB-JWT, the Verifier sees `purchase_id` in the chain-aware claims.
    #[tokio::test]
    async fn delegate_payload_injects_purchase_id() {
        use crate::vc::claims::Claim;

        let (vc, hld_kh) = issue_sd_jwt().await;

        let kms = LocalKms::new();
        let (_, delegate_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let delegate_jwk: ssi::jwk::JWK = delegate_kh.jwk().expect("delegate JWK");
        let delegate_jwk_value = serde_json::to_value(&delegate_jwk).unwrap();

        let dsd_jwt = DsdJwtAPI::create_delegated_credential(
            &vc,
            hld_kh,
            DelegationParams {
                delegate_payloads: vec![json!({
                    "purchase_id": "P-123",
                    "cnf": { "jwk": delegate_jwk_value },
                })],
                claims_to_disclose: Some(Map::new()),
                drop_disclosures: None,
                binding: ChainBindingMode::SdHash,
                ..Default::default()
            },
        )
        .await
        .expect("delegation with purchase_id should succeed");

        let nonce = Nonce::from_secret("merchant-nonce".to_string());
        let verifier_id = "merchant.example".to_string();

        let presentation = SdJwtAPI::create_vp(
            &dsd_jwt,
            delegate_kh,
            VPMetadata {
                disclosures: Map::new(),
                holder_binder: Some(HolderBinder {
                    nonce: nonce.clone(),
                    verifier_id: verifier_id.clone(),
                    response_uri: None,
                }),
            },
            UniversalResolver::default(),
        )
        .await
        .expect("delegate presents with KB-JWT");

        let verified = SdJwtAPI::verify_vp(
            &presentation,
            Some(HolderBinder {
                nonce,
                verifier_id,
                response_uri: None,
            }),
            VerifyOptions::default(),
            UniversalResolver::default(),
        )
        .await
        .expect("verifier validates chain + KB-JWT");

        assert_eq!(
            verified.get("purchase_id"),
            Some(&Claim::String("P-123".to_string())),
            "purchase_id injected by the delegate payload must appear in verified claims"
        );
    }

    /// Under `delegate-sd-jwt`, `HasClaims::parse_claims` on a stored dSD-JWT grant must layer
    /// the delegate payload on top of the issuer claims — so a delegate-injected claim (here
    /// `purchase_id`, absent from the issued credential) is visible to credential discovery /
    /// DCQL value-matching, while original issuer claims remain present.
    #[tokio::test]
    async fn parse_claims_surfaces_delegate_payload_claim() {
        use crate::vc::Credential as VcCredential;
        use crate::vc::claims::Claim;
        use crate::vc::formats::HasClaims;

        let (vc, hld_kh) = issue_sd_jwt().await;

        let dsd = DsdJwtAPI::create_delegated_credential(
            &vc,
            hld_kh,
            DelegationParams {
                delegate_payloads: vec![json!({ "purchase_id": "P-xyz" })],
                claims_to_disclose: Some(Map::new()),
                drop_disclosures: None,
                binding: ChainBindingMode::SdHash,
                ..Default::default()
            },
        )
        .await
        .expect("create_delegated_credential should succeed");

        let claims = VcCredential::SdJwt(dsd)
            .parse_claims()
            .expect("parse_claims should decode the dSD-JWT grant");

        assert_eq!(
            claims.get("purchase_id"),
            Some(&Claim::String("P-xyz".to_string())),
            "delegate-payload claim must be layered into parse_claims output"
        );
        // Original issuer claims must still be present.
        assert!(
            claims.get("iss").is_some(),
            "issuer claim 'iss' must remain present after layering"
        );
    }

    /// Holder binding: when `aud`/`nonce` are set, `create_delegated_credential` writes
    /// them into the delegate payload (a plain dSD-JWT's final KB-SD-JWT link is the key
    /// binding). The Verifier checks these against its expected audience/nonce; here we
    /// confirm they are present and Holder-signed (they survive the chain walk that
    /// verifies the link signature).
    #[tokio::test]
    async fn grant_binds_aud_and_nonce_in_delegate_payload() {
        let (vc, hld_kh) = issue_sd_jwt().await;

        let dsd = DsdJwtAPI::create_delegated_credential(
            &vc,
            hld_kh,
            DelegationParams {
                delegate_payloads: vec![json!({ "scope": "purchase" })],
                claims_to_disclose: Some(Map::new()),
                drop_disclosures: None,
                binding: ChainBindingMode::SdHash,
                aud: Some("verifier.example".to_string()),
                nonce: Some("nonce-abc".to_string()),
            },
        )
        .await
        .expect("create_delegated_credential should succeed");

        // The chain walk verifies the Holder's signature over the KB-SD-JWT link and
        // exposes the disclosed delegate payload — which must now carry aud/nonce.
        let view = DsdJwtAPI::verify_dsd_jwt(
            &dsd,
            UniversalResolver::default(),
            DsdJwtPurpose::Presentation(None),
        )
        .await
        .expect("verify_dsd_jwt should succeed");
        let payload = &view.delegate_payloads[0][0];
        assert_eq!(
            payload.get("aud").and_then(|v| v.as_str()),
            Some("verifier.example"),
            "aud must be bound into the delegate payload"
        );
        assert_eq!(
            payload.get("nonce").and_then(|v| v.as_str()),
            Some("nonce-abc"),
            "nonce must be bound into the delegate payload"
        );
        assert_eq!(
            payload.get("scope").and_then(|v| v.as_str()),
            Some("purchase"),
            "the requested delegate claims must be preserved alongside aud/nonce"
        );
    }

    #[tokio::test]
    async fn delegation_purpose_checks_holder_binding() {
        let (vc, hld_kh) = issue_sd_jwt().await;

        let dsd = DsdJwtAPI::create_delegated_credential(
            &vc,
            hld_kh,
            DelegationParams {
                delegate_payloads: vec![json!({ "scope": "checkout" }), json!({ "scope": "pay" })],
                claims_to_disclose: Some(Map::new()),
                drop_disclosures: None,
                binding: ChainBindingMode::SdHash,
                aud: Some("verifier.example".to_string()),
                nonce: Some("nonce-abc".to_string()),
            },
        )
        .await
        .expect("create_delegated_credential should succeed");

        let binder = |nonce: &str, aud: &str| {
            DsdJwtPurpose::Delegation(Some(HolderBinder {
                nonce: Nonce::from_secret(nonce.to_string()),
                verifier_id: aud.to_string(),
                response_uri: None,
            }))
        };

        let correct = DsdJwtAPI::verify_dsd_jwt(
            &dsd,
            UniversalResolver::default(),
            binder("nonce-abc", "verifier.example"),
        )
        .await;
        assert!(
            correct.is_ok(),
            "a grant bound to the request must verify: {:?}",
            correct.err()
        );

        for (nonce, aud) in [
            ("wrong-nonce", "verifier.example"),
            ("nonce-abc", "wrong-verifier.example"),
        ] {
            assert!(
                DsdJwtAPI::verify_dsd_jwt(&dsd, UniversalResolver::default(), binder(nonce, aud))
                    .await
                    .is_err(),
                "grant with nonce={nonce}, aud={aud} must be rejected"
            );
        }
    }

    #[tokio::test]
    async fn presentation_purpose_checks_holder_binding() {
        let (vc, hld_kh) = issue_sd_jwt().await;

        let dsd = DsdJwtAPI::create_delegated_credential(
            &vc,
            hld_kh,
            DelegationParams {
                delegate_payloads: vec![json!({ "scope": "purchase" })],
                claims_to_disclose: Some(Map::new()),
                drop_disclosures: None,
                binding: ChainBindingMode::SdHash,
                aud: Some("verifier.example".to_string()),
                nonce: Some("nonce-abc".to_string()),
            },
        )
        .await
        .expect("create_delegated_credential should succeed");

        let correct = DsdJwtAPI::verify_dsd_jwt(
            &dsd,
            UniversalResolver::default(),
            DsdJwtPurpose::Presentation(Some(HolderBinder {
                nonce: Nonce::from_secret("nonce-abc".to_string()),
                verifier_id: "verifier.example".to_string(),
                response_uri: None,
            })),
        )
        .await;
        assert!(
            correct.is_ok(),
            "correct nonce/aud must verify: {:?}",
            correct.err()
        );

        let wrong_nonce = DsdJwtAPI::verify_dsd_jwt(
            &dsd,
            UniversalResolver::default(),
            DsdJwtPurpose::Presentation(Some(HolderBinder {
                nonce: Nonce::from_secret("wrong-nonce".to_string()),
                verifier_id: "verifier.example".to_string(),
                response_uri: None,
            })),
        )
        .await;
        assert!(wrong_nonce.is_err(), "wrong nonce must be rejected");

        let wrong_aud = DsdJwtAPI::verify_dsd_jwt(
            &dsd,
            UniversalResolver::default(),
            DsdJwtPurpose::Presentation(Some(HolderBinder {
                nonce: Nonce::from_secret("nonce-abc".to_string()),
                verifier_id: "wrong-verifier.example".to_string(),
                response_uri: None,
            })),
        )
        .await;
        assert!(wrong_aud.is_err(), "wrong aud must be rejected");
    }
}
