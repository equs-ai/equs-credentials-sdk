use async_trait::async_trait;
use jsonwebtoken::{DecodingKey, Header};
use sd_jwt_rs::resolver::KeyResolver;
use sd_jwt_rs::{
    ClaimsForSelectiveDisclosureStrategy, SDJWTHolder, SDJWTIssuer, SDJWTSerializationFormat,
    SDJWTVerifier,
};
use serde_json::{Map, Value};
use snafu::{ensure, ResultExt};
use ssi::did::VerificationMethod;
use ssi::jwk::JWK;
use std::collections::HashMap;
use tracing::{instrument, trace, Level};

use crate::crypto::{Key, Signer};
use crate::did::universal::UniversalResolver;
use crate::did::{DIDDoc, DIDResolver, VerificationMethodMap, DIDURL};
use crate::nonce::Nonce;
use crate::utils;
use crate::utils::b64;
use crate::utils::serde::Helpers;
use crate::vc::core::PresentationInput;
use crate::vc::formats::vc::SD_JWT_VC;
use crate::vc::formats::{
    ClaimsResolvingSnafu, HasClaims, HasCredential, JWSSnafu, KeyTypeNotSupportedSnafu,
    ParsingSnafu, PresentationSnafu, SigningSnafu, VerifyOptions, VerifyingSnafu, API,
};
use crate::vc::formats::{GetExpirationClaim, Result};

pub type SdJwtRsError = sd_jwt_rs::error::Error;

pub type Credential = String;
pub type Presentation = String;
pub type Claims = Map<String, Value>;

pub struct SignerWrapper<S: Signer> {
    signer: S,
}

#[async_trait]
impl<S: Signer> sd_jwt_rs::signer::SDJWTSigner for SignerWrapper<S> {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        ret(),
    )]
    fn algorithm(&self) -> &str {
        let alg = self.signer.alg();
        alg.into()
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(),
    )]
    async fn sign(&self, message: &[u8]) -> sd_jwt_rs::error::Result<String> {
        let signed = self.signer.sign(message).await;
        signed
            .map(|v| b64::encode(&v))
            .map_err(|e| SdJwtRsError::SigningError(e.to_string()))
    }
}

pub struct DidKeyResolver<R: DIDResolver>(R);

impl<R: DIDResolver> DidKeyResolver<R> {
    #[instrument(
        level = Level::TRACE,
        skip_all
    )]
    pub fn new(did_resolver: R) -> DidKeyResolver<R> {
        DidKeyResolver(did_resolver)
    }
}

impl Default for DidKeyResolver<UniversalResolver> {
    #[instrument(
        level = Level::TRACE,
        skip_all
    )]
    fn default() -> Self {
        DidKeyResolver::new(UniversalResolver::new())
    }
}

#[async_trait]
impl<R: DIDResolver> KeyResolver for DidKeyResolver<R> {
    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
    )]
    async fn resolve(
        &self,
        did_url: &str,
        header: &Header,
    ) -> sd_jwt_rs::error::Result<DecodingKey> {
        let resolver = &self.0;

        let vm = resolver
            .resolve_verification_method(did_url)
            .await
            .map_err(|err| SdJwtRsError::Unspecified(err.to_string()))?;

        let jwk = vm
            .get_jwk()
            .map_err(|err| SdJwtRsError::DeserializationError(err.to_string()))?;

        let jwk = utils::jwk::from_spruce_jwk(&jwk)
            .ok_or_else(|| SdJwtRsError::Unspecified(format!("Unsupported key: {:?}", jwk)))?;

        DecodingKey::from_jwk(&jwk).map_err(|e| SdJwtRsError::DeserializationError(e.to_string()))
    }
}

// Metadata
#[derive(Debug, Default)]
pub struct VCMetadata {
    pub vct: String,
    pub lifetime: time::Duration,
    pub disclosures: Vec<String>,
}

#[derive(Debug, Default)]
pub struct VPMetadata {
    pub disclosures: Map<String, Value>,
}

impl HasClaims<Claims> for Credential {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(),
    )]
    fn parse_claims(&self) -> Result<Claims> {
        let stripped = SdJwtAPI::strip_disclosures(self)?;
        ssi::jwt::decode_unverified(stripped).context(JWSSnafu)
    }
}

impl HasCredential<Credential> for Presentation {
    #[instrument(
        level = Level::TRACE,
        skip_all,
        err(),
        ret(),
    )]
    fn get_credential(&self) -> Result<Credential> {
        // NOTE: returns basic VC w/o disclosures
        let stripped = SdJwtAPI::strip_disclosures(self)?;
        Ok(stripped.to_owned())
    }
}

pub struct SdJwtAPI;

impl SdJwtAPI {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    fn prepare_claims(
        mut claims: Claims,
        iss_did_url: &DIDURL,
        hld_did_url: &DIDURL,
        metadata: &VCMetadata,
    ) -> Value {
        claims.put_str("vct", &metadata.vct);
        claims.put_str("iss", &iss_did_url.did);
        claims.put_str("sub", &hld_did_url.did);

        let now = time::OffsetDateTime::now_utc();
        claims.put_dt("iat", now);
        claims.put_dt("nbf", now);

        let exp = Self::get_expiration_claim(&claims).unwrap_or(now + metadata.lifetime);
        claims.put_dt("exp", exp);

        Value::Object(claims)
    }

    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    fn extra_headers(iss_did_url: &DIDURL) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("typ".to_string(), SD_JWT_VC.to_string());
        headers.insert("kid".to_string(), iss_did_url.to_string());

        headers
    }

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(),
    )]
    pub fn strip_disclosures(vc: &Credential) -> Result<&str> {
        let mut parts = vc.split('~');

        parts.next().ok_or_else(|| {
            ParsingSnafu {
                details: "Strip disclosure failed for 'vc+sd_jwt' credential",
            }
            .build()
        })
    }

    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn verify_signature(vc: &Credential, jwk: &JWK) -> Result<()> {
        let stripped = Self::strip_disclosures(vc)?;

        ssi::jws::decode_verify(stripped, jwk).context(JWSSnafu)?;

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        err(),
        ret()
    )]
    fn get_vm_from_did_doc(did_doc: &DIDDoc) -> Result<&VerificationMethodMap> {
        let vm_methods = did_doc.verification_method.as_ref().ok_or(
            ParsingSnafu {
                details: "could not retrieve \"verification_method\" from DIDDoc",
            }
            .build(),
        )?;

        ensure!(
            vm_methods.len() == 1,
            ParsingSnafu {
                details: "DIDDoc contains multiple \"verification_method\""
            }
        );

        let vm = vm_methods.first().ok_or(
            ParsingSnafu {
                details: "\"verification_method\" list is empty",
            }
            .build(),
        )?;

        if let VerificationMethod::Map(vm) = vm {
            Ok(vm)
        } else {
            ParsingSnafu {
                details: "\"verification_method\" value must be embedded",
            }
            .fail()
        }
    }

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(),
    )]
    async fn get_vm_from_jwt(jwt: &str) -> Result<VerificationMethodMap> {
        let (header, payload) = ssi::jws::decode_unverified(jwt).context(JWSSnafu)?;
        let key_resolver = DidKeyResolver::default();

        let vm = match header.key_id {
            Some(did_url) => key_resolver
                .0
                .resolve_verification_method(&did_url)
                .await
                .map_err(|e| {
                    ParsingSnafu {
                        details: format!("could not resolve verification method: {e}"),
                    }
                    .build()
                })?,
            _ => {
                let claims: Claims = serde_json::from_slice(&payload).map_err(|err| {
                    ParsingSnafu {
                        details: err.to_string(),
                    }
                    .build()
                })?;

                let iss_value = claims.get("iss").ok_or(
                    VerifyingSnafu {
                        details: "could not retrieve \"iss\" field",
                    }
                    .build(),
                )?;
                let iss_did = serde_json::to_string(iss_value).map_err(|err| {
                    ParsingSnafu {
                        details: err.to_string(),
                    }
                    .build()
                })?;

                let did_doc = key_resolver
                    .0
                    .resolve(&iss_did, Default::default())
                    .await
                    .doc
                    .ok_or(
                        ParsingSnafu {
                            details: "could not retrieve \"DIDDoc\"",
                        }
                        .build(),
                    )?;

                Self::get_vm_from_did_doc(&did_doc)
                    .map_err(|e| {
                        ParsingSnafu {
                            details: format!("could not resolve verification method: {e}"),
                        }
                        .build()
                    })?
                    .to_owned()
            }
        };

        Ok(vm)
    }

    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    pub fn resolve_disclosures(input: &PresentationInput) -> Result<Map<String, Value>> {
        trace!(presentation_input = ?input);

        let claims = input.constraints.clone();

        let stripped: Vec<_> = claims
            .fields()
            .iter()
            .flat_map(|f| {
                f.path().iter().map(|p| {
                    let value = if f.is_optional() {
                        Value::String("optional".to_string())
                    } else {
                        Value::Bool(true)
                    };

                    (p.as_str(), value)
                })
            })
            .collect();

        let json = utils::json::paths_to_json(stripped).map_err(|e| {
            ParsingSnafu {
                details: format!("could parse json paths: {e}"),
            }
            .build()
        })?;

        let json_obj = json
            .as_object()
            .ok_or_else(|| {
                ParsingSnafu {
                    details: "could not convert json into json object",
                }
                .build()
            })?
            .to_owned();

        Ok(json_obj)
    }
}

impl GetExpirationClaim<Claims, time::OffsetDateTime> for SdJwtAPI {
    fn get_expiration_claim(claims: &Claims) -> Option<time::OffsetDateTime> {
        claims
            .get("exp")
            .and_then(|v| {
                serde_json::from_value::<i64>(v.to_owned())
                    .map(|exp| time::OffsetDateTime::from_unix_timestamp(exp).ok())
                    .ok()
            })
            .unwrap_or(None)
    }
}

#[async_trait]
impl API<Claims, Credential, Presentation, VCMetadata, VPMetadata, Value> for SdJwtAPI {
    #[instrument(
        level = Level::TRACE,
        ret(),
    )]
    fn resolve_claims(value: &Value) -> Result<Claims> {
        let claims = value.as_object().ok_or_else(|| {
            ClaimsResolvingSnafu {
                details: "The value is not an object",
            }
            .build()
        })?;

        Ok(claims.to_owned())
    }

    #[instrument(
        level = Level::TRACE,
        skip(issuer_data, holder_data),
        err(),
        ret(),
    )]
    async fn create_vc<S, K>(
        claims: Claims,
        issuer_data: (&DIDURL, S),
        holder_data: (&DIDURL, K),
        metadata: VCMetadata,
    ) -> Result<Credential>
    where
        S: Signer,
        K: Key,
    {
        trace!(issuer_did_url = ?{issuer_data.0}, holder_did_url = ?{holder_data.0});

        let (iss_did_url, signer) = issuer_data;
        let (hld_did_url, hld_key) = holder_data;

        let sgn_wrapper = SignerWrapper { signer };

        let claims = SdJwtAPI::prepare_claims(claims, iss_did_url, hld_did_url, &metadata);
        let headers = SdJwtAPI::extra_headers(iss_did_url);
        trace!(resolved_headers = ?headers);

        let jwk = utils::jwk::from_spruce_jwk_opt(hld_key.jwk()).ok_or_else(|| {
            KeyTypeNotSupportedSnafu {
                type_: "JWK incompatible",
            }
            .build()
        })?;
        trace!(resolved_holder_jwk = ?jwk);

        let disclosures = metadata.disclosures.iter().map(|d| d.as_str()).collect();
        trace!(resolved_disclosures = ?disclosures);

        let mut issuer = SDJWTIssuer::new(sgn_wrapper);

        issuer
            .issue_sd_jwt(
                claims,
                ClaimsForSelectiveDisclosureStrategy::Custom(disclosures),
                Some(jwk),
                false,
                SDJWTSerializationFormat::Compact,
                Some(headers),
            )
            .await
            .map_err(|err| {
                SigningSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }

    #[instrument(
        level = Level::TRACE,
        skip(holder_signer),
        err(),
        ret(),
    )]
    async fn create_vp<S>(
        credential: &Credential,
        holder_signer: S,
        nonce: &Nonce,
        verifier_id: &str,
        metadata: VPMetadata,
    ) -> Result<Presentation>
    where
        S: Signer,
    {
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

        holder
            .create_presentation(
                metadata.disclosures,
                Some(nonce.secret().to_owned()),
                Some(verifier_id.to_string()),
                Some(sgn_wrapper),
            )
            .await
            .map_err(|err| {
                PresentationSnafu {
                    details: err.to_string(),
                }
                .build()
            })
    }

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(),
    )]
    async fn verify_vc(credential: &Credential, opts: VerifyOptions) -> Result<()> {
        let plain_jwt = Self::strip_disclosures(credential)?;
        let vm = Self::get_vm_from_jwt(plain_jwt).await?;

        let jwk = vm.get_jwk().map_err(|e| {
            VerifyingSnafu {
                details: format!("could not retrieve JWK: {e}"),
            }
            .build()
        })?;

        Self::verify_signature(credential, &jwk)
    }

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(),
    )]
    async fn verify_vp(
        presentation: &Presentation,
        nonce: &Nonce,
        verifier_id: &str,
        _opts: VerifyOptions,
    ) -> Result<Value> {
        let key_resolver = DidKeyResolver::default();
        let mut verifier = SDJWTVerifier::new(Box::new(key_resolver));

        verifier
            .verify_presentation(
                presentation.to_owned(),
                Some(verifier_id.to_string()),
                Some(nonce.secret().to_string()),
                SDJWTSerializationFormat::Compact,
            )
            .await
            .map_err(|e| {
                VerifyingSnafu {
                    details: e.to_string(),
                }
                .build()
            })
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::Key;
    use crate::did::didkey::DIDKey;
    use crate::did::{DIDResolver, DIDURL};
    use crate::inmem::kms::LocalKms;
    use crate::inmem::nonce::LocalNonceGenerator;
    use crate::kms::{CreateOptions, KeyHandle, KeyType, Kms};
    use crate::nonce::{Nonce, NonceGenerator};
    use crate::utils::serde::Helpers;
    use crate::utils::test_utils::{create_did_url_and_key_handle, no_jwk_key};
    use crate::vc::formats::sd_jwt_vc::{Claims, Credential, SdJwtAPI, VCMetadata, VPMetadata};
    use crate::vc::formats::{Error, HasClaims, HasCredential, VerifyOptions, API};
    use rstest::rstest;
    use serde_json::json;
    use std::str::FromStr;

    #[rstest]
    #[case::p256(KeyType::P256)]
    #[case::ed25519(KeyType::Ed25519)]
    #[tokio::test]
    async fn sd_jwt_work_correctly_for_all_supported_keys(#[case] kt: KeyType) {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, kt.clone()).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, kt.clone()).await;
        let iss_jwk = iss_kh.clone().jwk().unwrap();

        let vc = SdJwtAPI::create_vc(
            sample_claims(),
            (&iss_did_url, iss_kh.clone()),
            (&hld_did_url, hld_kh.clone()),
            sample_vc_metadata(),
        )
        .await
        .unwrap();

        SdJwtAPI::verify_vc(&vc, Default::default()).await.unwrap();

        let claims = vc.parse_claims().unwrap();
        assert!(!claims.contains_key("name"));
        assert!(!claims.contains_key("surname"));
        assert_eq!(claims.get("dob").unwrap(), "09/09/1989");
        assert_eq!(claims.get("sub").unwrap(), &hld_did_url.did);
        assert_eq!(claims.get("iss").unwrap(), &iss_did_url.did);
        assert_eq!(claims.get("vct").unwrap(), "https://issuer.net/cred_schema");

        let nonce = random_nonce().await;
        let vp = SdJwtAPI::create_vp(
            &vc,
            hld_kh.clone(),
            &nonce,
            "verifier-id",
            sample_vp_metadata(),
        )
        .await
        .unwrap();

        let vc_from_vp = vp.get_credential().unwrap();
        SdJwtAPI::verify_signature(&vc_from_vp, &iss_jwk).unwrap();

        let disclosed = SdJwtAPI::verify_vp(&vp, &nonce, "verifier-id", VerifyOptions {})
            .await
            .unwrap();
        let disclosed = disclosed.as_object().unwrap();

        assert!(disclosed.contains_key("name"));
        assert_eq!(disclosed["name"], "John");
        assert!(!disclosed.contains_key("surname"));
    }

    #[tokio::test]
    async fn sd_jwt_create_vp_works_when_disclosure_is_optional() {
        let kms = LocalKms::new();
        let (vc, hld_kh) = sample_sd_jwt_vc_with_hld_kh().await;
        let nonce = &random_nonce().await;
        let verifier_id = "verifier-id";

        let vp = SdJwtAPI::create_vp(
            &vc,
            hld_kh,
            nonce,
            verifier_id,
            VPMetadata {
                disclosures: json!({
                    "optional_claim" : "optional",
                    "name": "optional",
                })
                .as_object()
                .unwrap()
                .to_owned(),
            },
        )
        .await
        .unwrap();

        let disclosed = SdJwtAPI::verify_vp(&vp, nonce, verifier_id, VerifyOptions {})
            .await
            .unwrap();

        let disclosed = disclosed.as_object().unwrap();

        assert!(!disclosed.contains_key("optional_claim"));
        assert!(disclosed.contains_key("name"));
        assert_eq!(disclosed["name"], "John");
    }

    #[tokio::test]
    async fn sd_jwt_create_vc_fails_on_invalid_claim() {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let mut claims = sample_claims();
        claims.put_str("_sd", "should be empty");

        let res = SdJwtAPI::create_vc(
            claims,
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh),
            sample_vc_metadata(),
        )
        .await;

        assert!(matches!(res.err(), Some(Error::Signing { .. })));
    }

    #[tokio::test]
    async fn sd_jwt_create_vc_fails_on_invalid_key() {
        let kms = LocalKms::new();
        let hld_did_url = DIDURL::from_str("did:example:123").unwrap();
        let hld_kh = no_jwk_key();
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let res = SdJwtAPI::create_vc(
            sample_claims(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh),
            sample_vc_metadata(),
        )
        .await;

        assert!(matches!(res.err(), Some(Error::KeyTypeNotSupported { .. })));
    }

    #[tokio::test]
    async fn sd_jwt_verify_vc_fails_on_invalid_cred() {
        let res = SdJwtAPI::verify_vc(&"not-a-valid-sd-jwt".to_string(), Default::default()).await;
        assert!(matches!(res.err(), Some(Error::JWS { .. })));
    }

    #[tokio::test]
    async fn sd_jwt_verify_vc_fails_on_resolving_vm() {
        let vc = sample_sd_jwt_vc_did_example().await;

        let res = SdJwtAPI::verify_vc(&vc, Default::default()).await;
        assert!(matches!(res.err(), Some(Error::Parsing { .. })));
    }

    #[tokio::test]
    async fn sd_jwt_verify_signature_fails_on_wrong_key() {
        let (vc, _) = sample_sd_jwt_vc_with_hld_kh().await;

        let kms = LocalKms::new();
        let (_, another_iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let another_iss_jwk = another_iss_kh.jwk().unwrap();

        let res = SdJwtAPI::verify_signature(&vc, &another_iss_jwk);
        assert!(matches!(res.err(), Some(Error::JWS { .. })));
    }

    #[tokio::test]
    async fn sd_jwt_create_vp_fails_on_invalid_credential() {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let res = SdJwtAPI::create_vp(
            &"not-a-valid-sd-jwt".to_string(),
            hld_kh,
            &random_nonce().await,
            "verifier-id",
            sample_vp_metadata(),
        )
        .await;

        assert!(matches!(res.err(), Some(Error::Signing { .. })));
    }

    #[tokio::test]
    async fn sd_jwt_create_vp_fails_when_disclosure_not_found() {
        let kms = LocalKms::new();
        let (vc, hld_kh) = sample_sd_jwt_vc_with_hld_kh().await;

        let res = SdJwtAPI::create_vp(
            &vc,
            hld_kh,
            &random_nonce().await,
            "verifier-id",
            VPMetadata {
                disclosures: json!({
                    "some_other_claim" : true
                })
                .as_object()
                .unwrap()
                .to_owned(),
            },
        )
        .await;

        assert!(matches!(res.err(), Some(Error::Presentation { .. })));
    }

    #[tokio::test]
    async fn sd_jwt_verify_vp_fails_on_invalid_vp() {
        let res = SdJwtAPI::verify_vp(
            &"not-a-valid-vp".to_string(),
            &random_nonce().await,
            "verifier-id",
            VerifyOptions {},
        )
        .await;

        assert!(matches!(res.err(), Some(Error::Verifying { .. })));
    }

    #[tokio::test]
    async fn sd_jwt_verify_vp_fails_on_vp_signed_by_another_key() {
        let (vc, _) = sample_sd_jwt_vc_with_hld_kh().await;

        let kms = LocalKms::new();
        let (_, kh) = kms
            .create_and_handle(KeyType::P256, CreateOptions {})
            .await
            .unwrap();

        let nonce = random_nonce().await;
        // VP can be generated using another signature
        let vp = SdJwtAPI::create_vp(&vc, kh, &nonce, "verifier-id", sample_vp_metadata())
            .await
            .unwrap();

        // But Verifier should deny it
        let res = SdJwtAPI::verify_vp(&vp, &nonce, "verifier-id", VerifyOptions {}).await;

        assert!(matches!(res.err(), Some(Error::Verifying { .. })));
    }

    #[tokio::test]
    async fn get_vm_from_did_doc_works_for_didkey() {
        let kms = LocalKms::new();
        let (_, kh) = kms
            .create_and_handle(KeyType::P256, CreateOptions {})
            .await
            .unwrap();

        let didkey = DIDKey::new();
        let did = didkey.generate(kh).unwrap();
        let did_doc = didkey.resolve(&did, Default::default()).await.doc.unwrap();

        let vm = SdJwtAPI::get_vm_from_did_doc(&did_doc).unwrap();
        assert!(vm.id.starts_with(&did));
    }

    async fn sample_sd_jwt_vc_with_hld_kh() -> (Credential, impl KeyHandle) {
        let kms = LocalKms::new();

        let (hld_did_url, h_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, i_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let vc = SdJwtAPI::create_vc(
            sample_claims(),
            (&iss_did_url, i_kh),
            (&hld_did_url, h_kh.clone()),
            sample_vc_metadata(),
        )
        .await
        .unwrap();

        (vc, h_kh)
    }

    async fn sample_sd_jwt_vc_did_example() -> Credential {
        let kms = LocalKms::new();

        let (hld_did_url, h_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let iss_did_url = DIDURL::from_str("did:example:123").unwrap();
        let (_, i_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        SdJwtAPI::create_vc(
            sample_claims(),
            (&iss_did_url, i_kh),
            (&hld_did_url, h_kh.clone()),
            sample_vc_metadata(),
        )
        .await
        .unwrap()
    }

    async fn random_nonce() -> Nonce {
        LocalNonceGenerator::default().generate().await.unwrap()
    }

    fn sample_claims() -> Claims {
        json!( {
            "name": "John",
            "surname": "Doe",
            "dob": "09/09/1989",
        })
        .as_object()
        .unwrap()
        .clone()
    }

    fn sample_vc_metadata() -> VCMetadata {
        VCMetadata {
            vct: "https://issuer.net/cred_schema".to_owned(),
            lifetime: time::Duration::days(365),
            disclosures: vec!["$.name".to_owned(), "$.surname".to_owned()],
        }
    }

    fn sample_vp_metadata() -> VPMetadata {
        VPMetadata {
            disclosures: json!({
                "name" : true
            })
            .as_object()
            .unwrap()
            .to_owned(),
        }
    }
}
