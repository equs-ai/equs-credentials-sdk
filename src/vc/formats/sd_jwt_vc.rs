use async_trait::async_trait;
use jsonwebtoken::{DecodingKey, Header};
use sd_jwt_rs::resolver::KeyResolver;
use sd_jwt_rs::utils::decode_sd_jwt;
use sd_jwt_rs::{
    ClaimsForSelectiveDisclosureStrategy, SDJWTHolder, SDJWTIssuer, SDJWTSerializationFormat,
    SDJWTVerifier,
};
use serde_json::{Map, Value};
use snafu::ResultExt;
use ssi::dids::DIDResolver;
use ssi::jwk::{JWKResolver, JWK};
use std::borrow::Cow;
use std::collections::HashMap;
use std::ops::Deref;
use tracing::{instrument, trace, Level};

use crate::crypto::{Key, Signer};
use crate::did::universal::UniversalResolver;
use crate::did::DIDURL;
use crate::nonce::Nonce;
use crate::utils;
use crate::utils::b64;
use crate::utils::serde::Helpers;
use crate::vc::core::{PresentationInput, PresentationRestriction};
use crate::vc::formats::vc::SD_JWT_VC;
use crate::vc::formats::{
    resolve_verification_method, ClaimsSnafu, HasClaims, HasCredential, JWSSnafu,
    KeyTypeNotSupportedSnafu, ParsingSnafu, PresentationSnafu, ProofValidationSnafu, SigningSnafu,
    VerifyOptions, VerifyingSnafu, API,
};
use crate::vc::formats::{GetDateTimeClaim, Result};

pub(crate) const VCT_CLAIM: &str = "vct";
pub(crate) const EXP_CLAIM: &str = "exp";
pub(crate) const NBF_CLAIM: &str = "nbf";
pub(crate) const IAT_CLAIM: &str = "iat";
const ISS_CLAIM: &str = "iss";
const SUB_CLAIM: &str = "sub";
const CNF_CLAIM: &str = "cnf";
const STATUS_CLAIM: &str = "status";
const ALWAYS_REVEALED_CLAIMS: [&str; 6] = [
    ISS_CLAIM,
    NBF_CLAIM,
    EXP_CLAIM,
    CNF_CLAIM,
    VCT_CLAIM,
    STATUS_CLAIM,
];

pub type SdJwtRsError = sd_jwt_rs::error::Error;

pub use crate::vc::claims::Claims;
pub type Credential = String;
pub type Presentation = String;

pub struct SignerWrapper<S: Signer> {
    signer: S,
}

#[async_trait]
impl<S: Signer> sd_jwt_rs::signer::SDJWTSigner for SignerWrapper<S> {
    #[instrument(level = Level::TRACE, skip(self), ret())]
    fn algorithm(&self) -> &str {
        let alg = self.signer.alg();
        alg.into()
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn sign(&self, message: &[u8]) -> sd_jwt_rs::error::Result<String> {
        let signed = self.signer.sign(message).await;
        signed
            .map(|v| b64::encode(&v))
            .map_err(|e| SdJwtRsError::SigningError(e.to_string()))
    }
}

pub struct DidKeyResolver<R: JWKResolver>(R);

impl<R: JWKResolver> DidKeyResolver<R> {
    #[instrument(level = Level::TRACE, skip_all)]
    pub fn new(did_resolver: R) -> DidKeyResolver<R> {
        DidKeyResolver(did_resolver)
    }
}

#[async_trait]
impl Default for DidKeyResolver<UniversalResolver> {
    #[instrument(level = Level::TRACE, skip_all)]
    fn default() -> Self {
        DidKeyResolver::new(UniversalResolver {})
    }
}

#[async_trait]
impl KeyResolver for DidKeyResolver<UniversalResolver> {
    #[instrument(level = Level::TRACE, skip(self), err())]
    async fn resolve(&self, did: &str, header: &Header) -> sd_jwt_rs::error::Result<DecodingKey> {
        let vm = self
            .0
            .resolve_into_any_verification_method(ssi::dids::DID::new(did).map_err(|e| {
                SdJwtRsError::Unspecified(format!("could not resolve verification method: {e}"))
            })?)
            .await
            .map_err(|e| SdJwtRsError::Unspecified(e.to_string()))?
            .ok_or_else(|| SdJwtRsError::Unspecified("empty verification method".to_string()))?;

        let jwk = self
            .0
            .fetch_public_jwk(Some(vm.id.as_str()))
            .await
            .map_err(|e| SdJwtRsError::Unspecified("could not resolve public jwk".to_string()))?;
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
    // TODO: should we change it to Claims?
    pub disclosures: Map<String, Value>,
}

impl HasClaims<Claims> for Credential {
    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    fn parse_claims(&self) -> Result<Claims> {
        let mut value = decode_sd_jwt(self.to_string(), SDJWTSerializationFormat::Compact)
            .map_err(|err| {
                ParsingSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        if let Some(obj) = value.as_object_mut() {
            obj.remove(CNF_CLAIM);
        }

        let claims = value.try_into().context(ClaimsSnafu)?;
        Ok(claims)
    }
}

impl HasCredential<Credential> for Presentation {
    #[instrument(level = Level::TRACE, skip_all, err(), ret())]
    fn get_credential(&self) -> Result<Credential> {
        // NOTE: returns basic VC w/o disclosures
        let stripped = SdJwtAPI::strip_disclosures(self)?;
        Ok(stripped.to_owned())
    }
}

pub struct SdJwtAPI;

impl SdJwtAPI {
    #[instrument(level = Level::TRACE, ret())]
    fn prepare_claims(
        mut claims: Claims,
        iss_did_url: &DIDURL,
        hld_did_url: &DIDURL,
        metadata: &VCMetadata,
    ) -> Claims {
        claims.put_str(VCT_CLAIM, &metadata.vct);
        claims.put_str(ISS_CLAIM, iss_did_url.did());
        claims.put_str(SUB_CLAIM, hld_did_url.did());

        let iat =
            get_time_based_claim(&claims, IAT_CLAIM).unwrap_or_else(time::OffsetDateTime::now_utc);
        let nbf =
            get_time_based_claim(&claims, NBF_CLAIM).unwrap_or_else(time::OffsetDateTime::now_utc);
        claims.put_dt(IAT_CLAIM, iat);
        claims.put_dt(NBF_CLAIM, nbf);

        let exp = Self::get_date_time_claim(EXP_CLAIM, &claims)
            .unwrap_or_else(|| time::OffsetDateTime::now_utc() + metadata.lifetime);
        claims.put_dt(EXP_CLAIM, exp);

        claims
    }

    #[instrument(level = Level::TRACE, ret())]
    fn extra_headers(iss_did_url: &DIDURL) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        headers.insert("typ".to_string(), SD_JWT_VC.to_string());
        headers.insert("kid".to_string(), iss_did_url.to_string());

        headers
    }

    #[instrument(level = Level::TRACE, err(), ret())]
    pub fn strip_disclosures(vc: &Credential) -> Result<&str> {
        let mut parts = vc.split('~');

        parts.next().ok_or_else(|| {
            ParsingSnafu {
                details: "Strip disclosure failed for 'vc+sd_jwt' credential",
            }
            .build()
        })
    }

    #[instrument(level = Level::TRACE, ret())]
    pub fn verify_signature(vc: &Credential, jwk: &JWK) -> Result<()> {
        let stripped = Self::strip_disclosures(vc)?;

        ssi::claims::jws::decode_verify(stripped, jwk).context(JWSSnafu)?;

        Ok(())
    }

    #[instrument(level = Level::TRACE, err(), ret())]
    async fn get_jwk_from_jwt(jwt: &str) -> Result<Cow<JWK>> {
        let (header, payload) = ssi::claims::jws::decode_unverified(jwt).context(JWSSnafu)?;
        let resolver = UniversalResolver::default();

        let vm = match header.key_id {
            Some(did_url) => resolver
                .fetch_public_jwk(Some(&did_url))
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

                let iss_value = claims.get(ISS_CLAIM).ok_or(
                    VerifyingSnafu {
                        details: "could not retrieve \"iss\" field from sd-jwt header",
                    }
                    .build(),
                )?;
                let iss_did = serde_json::to_string(iss_value).map_err(|err| {
                    ParsingSnafu {
                        details: err.to_string(),
                    }
                    .build()
                })?;

                let vm = resolve_verification_method(&iss_did).await?;
                resolver
                    .fetch_public_jwk(Some(vm.id.as_str()))
                    .await
                    .context(ProofValidationSnafu)?
            }
        };

        Ok(Cow::Owned(vm.deref().clone()))
    }

    #[instrument(level = Level::TRACE, ret())]
    pub fn resolve_disclosures(input: &PresentationInput) -> Result<Map<String, Value>> {
        trace!(presentation_input = ?input);

        let claims = Self::resolve_claims_for_restriction(&input.restrictions);

        let stripped: Vec<(&str, Value)> = claims
            .into_iter()
            .map(|(key, optional)| {
                let value = if optional {
                    Value::String("optional".to_string())
                } else {
                    Value::Bool(true)
                };

                (key, value)
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

    fn resolve_claims_for_restriction(
        restrictions: &[PresentationRestriction],
    ) -> HashMap<&str, bool> {
        let mut field_map = HashMap::new();

        for restriction in restrictions {
            for field in &restriction.fields {
                field_map
                    .entry(field.as_str())
                    .and_modify(|disclosure| *disclosure &= restriction.optional)
                    .or_insert(restriction.optional);
            }
        }

        field_map
    }
}

impl GetDateTimeClaim<Claims, time::OffsetDateTime> for SdJwtAPI {
    fn get_date_time_claim(exp: &str, claims: &Claims) -> Option<time::OffsetDateTime> {
        get_time_based_claim(claims, exp)
    }
}

fn get_time_based_claim(claims: &Claims, key: &str) -> Option<time::OffsetDateTime> {
    claims
        .get(key)
        .and_then(|v| v.as_int())
        .and_then(|v| time::OffsetDateTime::from_unix_timestamp(*v).ok())
}

#[async_trait]
impl API<Claims, Credential, Presentation, VCMetadata, VPMetadata, Claims> for SdJwtAPI {
    #[instrument(level = Level::TRACE, skip(issuer_data, holder_data), err(), ret())]
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

        let disclosures = metadata
            .disclosures
            .iter()
            .map(|d| d.as_str())
            .filter(|d| {
                if let Some(claim) = d.strip_prefix("$.") {
                    return !ALWAYS_REVEALED_CLAIMS.contains(&claim);
                }
                true
            })
            .collect();
        trace!(resolved_disclosures = ?disclosures);

        let mut issuer = SDJWTIssuer::new(sgn_wrapper);
        let claims = claims.try_into().context(ClaimsSnafu)?;

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

    #[instrument(level = Level::TRACE, skip(holder_signer), err(), ret())]
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

    #[instrument(level = Level::TRACE, err(), ret())]
    async fn verify_vc(credential: &Credential, opts: VerifyOptions) -> Result<()> {
        let plain_jwt = Self::strip_disclosures(credential)?;
        let jwk = Self::get_jwk_from_jwt(plain_jwt).await?;

        Self::verify_signature(credential, &jwk)
    }

    #[instrument(level = Level::TRACE, err(), ret())]
    async fn verify_vp(
        presentation: &Presentation,
        nonce: &Nonce,
        verifier_id: &str,
        _opts: VerifyOptions,
    ) -> Result<Claims> {
        let key_resolver = DidKeyResolver::default();
        let mut verifier = SDJWTVerifier::new(Box::new(key_resolver));

        let claims_json = verifier
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
            })?;

        claims_json.try_into().context(ClaimsSnafu)
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::Key;
    use crate::did::didkey::DIDKey;
    use crate::did::universal::UniversalResolver;
    use crate::did::{DIDResolver, DIDURL};
    use crate::inmem::kms::LocalKms;
    use crate::inmem::nonce::LocalNonceGenerator;
    use crate::kms::{CreateOptions, KeyHandle, KeyType, Kms};
    use crate::nonce::{Nonce, NonceGenerator};
    use crate::utils::serde::Helpers;
    use crate::utils::test_utils::{create_did_url_and_key_handle, failed_signer_key, no_jwk_key};
    use crate::vc::claims::Claim;
    use crate::vc::formats::sd_jwt_vc::{
        Claims, Credential, SdJwtAPI, VCMetadata, VPMetadata, EXP_CLAIM, IAT_CLAIM, ISS_CLAIM,
        NBF_CLAIM, SUB_CLAIM, VCT_CLAIM,
    };
    use crate::vc::formats::{Error, HasClaims, HasCredential, VerifyOptions, API};
    use rstest::rstest;
    use serde_json::json;
    use std::ops::Add;
    use time::OffsetDateTime;

    #[rstest]
    #[case::p256(KeyType::P256)]
    #[case::ed25519(KeyType::Ed25519)]
    #[tokio::test]
    async fn sd_jwt_work_correctly_for_all_supported_keys(#[case] kt: KeyType) {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, kt.clone()).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, kt).await;
        let iss_jwk = iss_kh.jwk().unwrap();

        let mut claims = sample_claims();
        let exp = OffsetDateTime::now_utc()
            .add(time::Duration::days(365))
            .unix_timestamp();
        let nbf = OffsetDateTime::now_utc()
            .add(time::Duration::days(1))
            .unix_timestamp();
        let iat = OffsetDateTime::now_utc().unix_timestamp();
        claims.insert(EXP_CLAIM.to_string(), Claim::Int(exp));
        claims.insert(NBF_CLAIM.to_string(), Claim::Int(nbf));
        claims.insert(IAT_CLAIM.to_string(), Claim::Int(iat));

        let mut vc_metadata = sample_vc_metadata();
        vc_metadata.disclosures.extend_from_slice(&[
            format!("$.{EXP_CLAIM}"),
            format!("$.{NBF_CLAIM}"),
            format!("$.{IAT_CLAIM}"),
        ]);
        let vc = SdJwtAPI::create_vc(
            claims,
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh.clone()),
            vc_metadata,
        )
        .await
        .unwrap();

        SdJwtAPI::verify_vc(&vc, Default::default()).await.unwrap();

        let claims = vc.parse_claims().unwrap();
        assert!(claims.get("name").is_some());
        assert!(claims.get("surname").is_some());
        assert_eq!(
            claims.get("dob").unwrap(),
            &Claim::String("09/09/1989".to_string())
        );
        assert_eq!(
            claims.get(SUB_CLAIM).unwrap(),
            &Claim::String(hld_did_url.did().to_string())
        );
        assert_eq!(
            claims.get(ISS_CLAIM).unwrap(),
            &Claim::String(iss_did_url.did().to_string())
        );
        assert_eq!(
            claims.get(VCT_CLAIM).unwrap(),
            &Claim::String("https://issuer.net/cred_schema".to_string())
        );
        assert_eq!(claims.get(EXP_CLAIM).unwrap(), &Claim::Int(exp));
        assert_eq!(claims.get(NBF_CLAIM).unwrap(), &Claim::Int(nbf));
        assert_eq!(claims.get(IAT_CLAIM).unwrap(), &Claim::Int(iat));

        let nonce = random_nonce().await;
        let vp = SdJwtAPI::create_vp(&vc, hld_kh, &nonce, "verifier-id", sample_vp_metadata())
            .await
            .unwrap();

        let vc_from_vp = vp.get_credential().unwrap();
        SdJwtAPI::verify_signature(&vc_from_vp, &iss_jwk).unwrap();

        let disclosed = SdJwtAPI::verify_vp(&vp, &nonce, "verifier-id", VerifyOptions::default())
            .await
            .unwrap();

        assert!(disclosed.get("name").is_some());
        assert!(disclosed.get(EXP_CLAIM).is_some());
        assert!(disclosed.get(NBF_CLAIM).is_some());
        assert_eq!(
            disclosed.get("name").unwrap(),
            &Claim::String("John".to_string())
        );
        assert!(disclosed.get("surname").is_none());
        assert!(disclosed.get(IAT_CLAIM).is_none());
    }

    #[tokio::test]
    async fn sd_jwt_issuance_fails_in_case_of_signer_error() {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let result = SdJwtAPI::create_vc(
            sample_claims(),
            (&iss_did_url, failed_signer_key(iss_kh)),
            (&hld_did_url, hld_kh),
            sample_vc_metadata(),
        )
        .await;

        assert!(matches!(
            result.err().unwrap(),
            crate::vc::formats::Error::Signing { .. }
        ));
    }

    #[tokio::test]
    async fn sd_jwt_issuance_fails_in_case_of_jwk_error() {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let result = SdJwtAPI::create_vc(
            sample_claims(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, no_jwk_key()),
            sample_vc_metadata(),
        )
        .await;

        assert!(matches!(
            result.err().unwrap(),
            crate::vc::formats::Error::KeyTypeNotSupported { .. }
        ));
    }

    #[tokio::test]
    async fn sd_jwt_presentation_fails_in_case_of_signer_error() {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let vc = SdJwtAPI::create_vc(
            sample_claims(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh.clone()),
            sample_vc_metadata(),
        )
        .await
        .unwrap();

        let nonce = random_nonce().await;
        let result = SdJwtAPI::create_vp(
            &vc,
            failed_signer_key(hld_kh),
            &nonce,
            "verifier-id",
            sample_vp_metadata(),
        )
        .await;

        assert!(matches!(
            result.err().unwrap(),
            crate::vc::formats::Error::Presentation { .. }
        ));
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

        let disclosed = SdJwtAPI::verify_vp(&vp, nonce, verifier_id, VerifyOptions::default())
            .await
            .unwrap();

        assert!(disclosed.get("optional_claim").is_none());
        assert!(disclosed.get("name").is_some());
        assert_eq!(
            disclosed.get("name").unwrap(),
            &Claim::String("John".to_string())
        );
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
        let hld_did_url = DIDURL::new("did:example:123").unwrap();
        let hld_kh = no_jwk_key();
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let res = SdJwtAPI::create_vc(
            sample_claims(),
            (&iss_did_url, iss_kh),
            (hld_did_url, hld_kh),
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
            VerifyOptions::default(),
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
        let res = SdJwtAPI::verify_vp(&vp, &nonce, "verifier-id", VerifyOptions::default()).await;

        assert!(matches!(res.err(), Some(Error::Verifying { .. })));
    }

    #[tokio::test]
    async fn get_vm_from_did_doc_works_for_didkey() {
        let kms = LocalKms::new();
        let (_, kh) = kms
            .create_and_handle(KeyType::P256, CreateOptions {})
            .await
            .unwrap();

        let did = DIDKey::generate(kh).unwrap();
        let vm = UniversalResolver::default()
            .resolve_into_any_verification_method(ssi::dids::DID::new(&did).unwrap())
            .await
            .unwrap()
            .unwrap();

        assert!(vm.id.to_string().starts_with(&did));
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
        let iss_did_url = DIDURL::new("did:example:123").unwrap();
        let (_, i_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        SdJwtAPI::create_vc(
            sample_claims(),
            (iss_did_url, i_kh),
            (&hld_did_url, h_kh),
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
        .try_into()
        .unwrap()
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
