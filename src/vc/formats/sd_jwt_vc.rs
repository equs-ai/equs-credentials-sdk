use async_trait::async_trait;
use jsonwebtoken::{DecodingKey, Header};
use oid4vci::openidconnect::Nonce;
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
use time::OffsetDateTime;
use tracing::{instrument, trace, Level};

use crate::crypto::{Key, Signer};
use crate::did::universal::UniversalResolver;
use crate::did::{DIDDoc, DIDResolver, VerificationMethodMap, DID, DIDURL};
use crate::utils;
use crate::utils::b64;
use crate::utils::serde::Helpers;
use crate::vc::formats::vc::SD_JWT_VC;
use crate::vc::formats::Result;
use crate::vc::formats::{
    HasClaims, HasCredential, JWSSnafu, KeyTypeNotSupportedSnafu, ParsingSnafu, PresentationSnafu,
    SigningSnafu, VerifyOptions, VerifyingSnafu, API,
};

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
        ret(level = Level::TRACE),
    )]
    fn algorithm(&self) -> &str {
        let alg = self.signer.alg();
        alg.into()
    }

    #[instrument(
        level = Level::TRACE,
        skip(self),
        err(),
        ret(level = Level::TRACE),
    )]
    async fn sign(&self, message: &[u8]) -> sd_jwt_rs::error::Result<String> {
        let signed = self.signer.sign(message).await;
        signed
            .map(b64::encode)
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
        ret(level = Level::TRACE)
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
        ret(level = Level::TRACE)
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
        ret(level = Level::TRACE)
    )]
    fn prepare_claims(
        mut claims: Claims,
        iss_did: &DID,
        hld_did: &DID,
        metadata: &VCMetadata,
    ) -> Value {
        claims.put_str("vct", &metadata.vct);
        claims.put_str("iss", iss_did);
        claims.put_str("sub", hld_did);

        let now = OffsetDateTime::now_utc();
        claims.put_dt("iat", now);
        claims.put_dt("nbf", now);

        let lt = metadata.lifetime;
        claims.put_dt("exp", now + lt);

        Value::Object(claims)
    }

    #[instrument(
        level = Level::TRACE,
        ret(level = Level::TRACE)
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
        ret(level = Level::TRACE)
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
        ret(level = Level::TRACE)
    )]
    pub fn verify_signature(vc: &Credential, jwk: &JWK) -> Result<()> {
        let stripped = Self::strip_disclosures(vc)?;

        ssi::jws::decode_verify(stripped, jwk).context(JWSSnafu)?;

        Ok(())
    }

    #[instrument(
        level = Level::TRACE,
        err(),
        ret(level = Level::TRACE)
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
        ret(level = Level::TRACE)
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
}

#[async_trait]
impl API<Claims, Credential, Presentation, VCMetadata, VPMetadata, Value> for SdJwtAPI {
    #[instrument(
        level = Level::TRACE,
        ret(level = Level::TRACE)
    )]
    fn resolve_claims(value: &Value) -> Claims {
        value.as_object().unwrap().to_owned()
    }

    #[instrument(
        level = Level::TRACE,
        skip(issuer_data, holder_data),
        err(),
        ret(level = Level::TRACE)
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
        let (hld_did, hld_key) = holder_data;

        let sgn_wrapper = SignerWrapper { signer };

        let claims = SdJwtAPI::prepare_claims(claims, &iss_did_url.did, &hld_did.did, &metadata);
        let headers = SdJwtAPI::extra_headers(iss_did_url);
        trace!(resolved_headers = ?headers);

        let jwk = utils::jwk::from_spruce_jwk_opt(hld_key.jwk())
            .ok_or_else(|| KeyTypeNotSupportedSnafu { type_: "JWK" }.build())?;
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
        skip(holder_data),
        err(),
        ret(level = Level::TRACE)
    )]
    async fn create_vp<S>(
        credential: &Credential,
        holder_data: (&DIDURL, S),
        nonce: Nonce,
        verifier_id: &str,
        metadata: VPMetadata,
    ) -> Result<Presentation>
    where
        S: Signer,
    {
        trace!(holder_did_url = ?{holder_data.0});

        let (_, signer) = holder_data;
        let sgn_wrapper = SignerWrapper { signer };

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
        ret(level = Level::TRACE)
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
        ret(level = Level::TRACE)
    )]
    async fn verify_vp(
        presentation: &Presentation,
        nonce: Nonce,
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
    use std::str::FromStr;

    use oid4vci::openidconnect::Nonce;
    use serde_json::json;
    use ssi::did::DIDURL;

    use crate::crypto::Key;
    use crate::did::didkey::DIDKey;
    use crate::inmem::kms::LocalKms;
    use crate::kms;
    use crate::kms::Kms;
    use crate::vc::formats::sd_jwt_vc::{SdJwtAPI, VCMetadata, VPMetadata};
    use crate::vc::formats::{HasClaims, HasCredential, VerifyOptions, API};

    #[tokio::test]
    async fn e2e() {
        let kms = LocalKms::new();
        let didkey = DIDKey::new();

        for kt in [kms::KeyType::Ed25519, kms::KeyType::P256] {
            // Initialization
            let (_, i_kh) = kms
                .create_and_handle(kt.clone(), kms::CreateOptions {})
                .await
                .unwrap();
            let (_, h_kh) = kms
                .create_and_handle(kt, kms::CreateOptions {})
                .await
                .unwrap();

            let claims = json!( {
                "name": "John",
                "surname": "Doe",
                "dob": "09/09/1989",
            });

            let iss_did = didkey.generate(i_kh.clone()).unwrap();
            let iss_did_url = DIDURL::from_str(&iss_did).unwrap();
            println!("Iss DID: {}", iss_did);

            let hld_did = didkey.generate(h_kh.clone()).unwrap();
            let hld_did_url = DIDURL::from_str(&hld_did).unwrap();
            println!("Hld DID: {}", hld_did);

            let cl = claims.as_object().unwrap().clone();
            println!("Claims: {:?}", cl);

            let iss_jwk = i_kh.clone().jwk().unwrap();
            println!(
                "Iss JWK:\n{}",
                serde_json::to_string_pretty(&iss_jwk).unwrap()
            );
            let hld_jwk = h_kh.clone().jwk().unwrap();
            println!(
                "Hld JWK:\n{}",
                serde_json::to_string_pretty(&hld_jwk).unwrap()
            );

            // VC
            let vc_res = SdJwtAPI::create_vc(
                cl,
                (&iss_did_url, i_kh.clone()),
                (&hld_did_url, h_kh.clone()),
                VCMetadata {
                    vct: "https://issuer.net/cred_schema".to_owned(),
                    lifetime: time::Duration::days(365),
                    disclosures: vec!["$.name".to_owned(), "$.surname".to_owned()],
                },
            )
            .await;
            assert!(vc_res.is_ok());

            let vc = vc_res.unwrap();
            println!("VC:\n{}", vc);

            let claims = vc.parse_claims().unwrap();
            println!(
                "Claims:\n{}",
                serde_json::to_string_pretty(&claims).unwrap()
            );

            assert!(!claims.contains_key("name"));
            assert!(!claims.contains_key("surname"));
            assert_eq!(claims.get("dob").unwrap(), "09/09/1989");
            assert_eq!(claims.get("sub").unwrap(), &hld_did_url.to_string());
            assert_eq!(claims.get("iss").unwrap(), &iss_did_url.to_string());

            let sgn_res = SdJwtAPI::verify_signature(&vc, &iss_jwk);
            assert!(sgn_res.is_ok());

            // VP
            let nonce = Nonce::new_random();
            let vp_res = SdJwtAPI::create_vp(
                &vc,
                (&hld_did_url, h_kh.clone()),
                nonce.clone(),
                "verifier-id",
                VPMetadata {
                    disclosures: json!({
                        "name" : true
                    })
                    .as_object()
                    .unwrap()
                    .to_owned(),
                },
            )
            .await;
            assert!(vp_res.is_ok());

            let vp = vp_res.unwrap();
            println!("VP:\n{}", vp);

            let vc_from_vp = vp.get_credential().unwrap();
            let sgn_res = SdJwtAPI::verify_signature(&vc_from_vp, &iss_jwk);
            assert!(sgn_res.is_ok());

            // Verification
            let ver_res =
                SdJwtAPI::verify_vp(&vp, nonce.clone(), "verifier-id", VerifyOptions {}).await;
            assert!(ver_res.is_ok());

            let disclosed = ver_res.unwrap();
            println!("Disclosed: {}", disclosed);

            let disclosed = disclosed.as_object().unwrap();

            assert!(disclosed.contains_key("name"));
            assert_eq!(disclosed["name"], "John");
            assert!(!disclosed.contains_key("surname"));
        }
    }
}
