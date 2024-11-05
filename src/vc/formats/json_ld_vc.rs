use crate::crypto::{Key, Signer};
use crate::did::universal::UniversalResolver;
use crate::did::{DIDResolver, DIDURL};
use crate::nonce::Nonce;
use crate::utils::b64;
use crate::vc::formats::{
    ClaimsResolvingSnafu, CredentialCreationSnafu, FormatNotSupportedSnafu, GetExpirationClaim,
    HasClaims, HasCredential, KeyTypeNotSupportedSnafu, MultipleCredentialsNotSupportedSnafu,
    MultipleSubjectNotSupportedSnafu, NoCredentialSnafu, PresentationSnafu, ProofCompletionSnafu,
    Result, SigningSnafu, VerifyOptions, VerifyingSnafu, API,
};
use async_trait::async_trait;
use chrono::TimeDelta;
use serde_json::Value;
use snafu::ResultExt;
use ssi::vc::{
    Contexts, Credential, CredentialOrJWT, CredentialSubject, OneOrMany, Presentation, VCDateTime,
    ALT_DEFAULT_CONTEXT, DEFAULT_CONTEXT, DEFAULT_CONTEXT_V2, URI,
};
use ssi_ldp::{Context, ProofSuite, SigningInput};
use std::collections::HashMap;
use tracing::{instrument, trace, Level};

pub type Claims = HashMap<String, Value>;

const DEFAULT_VC_TYPE: &str = "VerifiableCredential";
const DEFAULT_VP_TYPE: &str = "VerifiablePresentation";

const DEFAULT_CRED_LIFETIME_DAYS: i64 = 5 * 365;

// Metadata
#[derive(Debug)]
pub struct VCMetadata {
    pub contexts: Contexts,
    pub type_: OneOrMany<String>,
    pub lifetime: TimeDelta,
}

impl VCMetadata {
    #[instrument(level = Level::TRACE, ret())]
    pub fn new(contexts: Vec<String>, types: Vec<String>) -> Self {
        let mut contexts = contexts;
        let mut types = types;

        let default_ctx_is_provided = contexts.iter().any(|ctx| {
            ctx == DEFAULT_CONTEXT || ctx == DEFAULT_CONTEXT_V2 || ctx == ALT_DEFAULT_CONTEXT
        });

        if !default_ctx_is_provided {
            contexts.push(DEFAULT_CONTEXT.to_string());
        }

        let contexts = match contexts.len() {
            1 => Contexts::One(Context::URI(URI::String(contexts[0].clone()))),
            _ => Contexts::Many(
                contexts
                    .into_iter()
                    .map(|uri| Context::URI(URI::String(uri)))
                    .collect(),
            ),
        };

        if !types.iter().any(|item| item == DEFAULT_VC_TYPE) {
            types.insert(0, DEFAULT_VC_TYPE.to_string());
        }

        let type_ = match types.len() {
            1 => OneOrMany::One(types[0].clone()),
            _ => OneOrMany::Many(types),
        };

        let lifetime = chrono::Duration::days(DEFAULT_CRED_LIFETIME_DAYS);

        Self {
            contexts,
            type_,
            lifetime,
        }
    }
}

#[derive(Debug)]
pub struct VPMetadata {
    pub contexts: Contexts,
    pub type_: OneOrMany<String>,
}

impl VPMetadata {
    #[instrument(level = Level::TRACE, ret())]
    pub fn new() -> Self {
        Self {
            contexts: Contexts::One(Context::URI(URI::String(DEFAULT_CONTEXT.to_string()))),
            type_: OneOrMany::One(DEFAULT_VP_TYPE.to_string()),
        }
    }
}

impl HasClaims<Claims> for Credential {
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn parse_claims(&self) -> Result<Claims> {
        match &self.credential_subject {
            OneOrMany::Many(cred_subjs) => MultipleSubjectNotSupportedSnafu {}.fail(),
            OneOrMany::One(cred_subject) => {
                let mut claims = HashMap::new();

                if let Some(URI::String(id)) = &cred_subject.id {
                    claims.insert("id".to_string(), Value::String(id.clone()));
                }

                if let Some(properties) = &cred_subject.property_set {
                    for (key, val) in properties.iter() {
                        claims.insert(key.clone(), val.clone());
                    }
                }

                Ok(claims)
            }
        }
    }
}

impl HasCredential<Credential> for Presentation {
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn get_credential(&self) -> Result<Credential> {
        let cred_or_jwt = match &self.verifiable_credential {
            None => return NoCredentialSnafu {}.fail(),
            Some(OneOrMany::One(cred)) => cred,
            Some(OneOrMany::Many(creds)) => match creds.len() {
                1 => &creds[0],
                0 => return NoCredentialSnafu {}.fail(),
                _ => return MultipleCredentialsNotSupportedSnafu {}.fail(),
            },
        };

        match cred_or_jwt {
            CredentialOrJWT::Credential(cred) => Ok(cred.clone()),
            CredentialOrJWT::JWT(_) => FormatNotSupportedSnafu { format: "JWT" }.fail(),
        }
    }
}

pub struct JsonLdAPI;

impl JsonLdAPI {
    #[instrument(level = Level::TRACE, ret())]
    fn create_credential(
        metadata: VCMetadata,
        iss_did: String,
        holder_did: String,
        claims: Claims,
    ) -> Credential {
        let now = chrono::Local::now();
        let exp_date = JsonLdAPI::get_expiration_claim(&claims)
            .unwrap_or(VCDateTime::from(now + metadata.lifetime));

        let credential_subject = OneOrMany::One(CredentialSubject {
            id: Some(URI::String(holder_did)),
            property_set: Some(claims),
        });
        let iss_date = VCDateTime::from(now);
        let issuer = Some(ssi::vc::Issuer::URI(URI::String(iss_did)));

        Credential {
            context: metadata.contexts,
            type_: metadata.type_,
            issuer,
            credential_subject,
            id: None,
            issuance_date: Some(iss_date),
            proof: None,
            expiration_date: Some(exp_date),
            credential_status: None,
            terms_of_use: None,
            evidence: None,
            credential_schema: None,
            refresh_service: None,
            property_set: None,
        }
    }

    #[instrument(level = Level::TRACE, ret())]
    fn create_presentation(
        vc: Credential,
        metadata: VPMetadata,
        holder_did: String,
    ) -> Presentation {
        let holder = Some(URI::String(holder_did));
        let verifiable_credential = Some(OneOrMany::One(CredentialOrJWT::Credential(vc)));

        Presentation {
            context: metadata.contexts,
            type_: metadata.type_,
            holder,
            verifiable_credential,
            id: None,
            proof: None,
            holder_binding: None,
            property_set: None,
        }
    }

    #[instrument(level = Level::TRACE, skip(signer), err(), ret())]
    async fn sign_proof(input: &SigningInput, signer: &impl Signer) -> Result<Vec<u8>> {
        match input {
            SigningInput::Bytes(bytes) => signer.sign(&bytes.0).await.map_err(|err| {
                SigningSnafu {
                    details: err.to_string(),
                }
                .build()
            }),
            _ => SigningSnafu {
                details: "Unsupported signing input",
            }
            .fail(),
        }
    }
}

impl GetExpirationClaim<Claims, VCDateTime> for JsonLdAPI {
    fn get_expiration_claim(claims: &Claims) -> Option<VCDateTime> {
        claims
            .get("expirationDate")
            .and_then(|v| serde_json::from_value(v.to_owned()).ok())
    }
}

#[async_trait]
impl API<Claims, Credential, Presentation, VCMetadata, VPMetadata, Value> for JsonLdAPI {
    #[instrument(level = Level::TRACE, ret())]
    fn resolve_claims(value: &Value) -> Result<Claims> {
        let mut claims = HashMap::new();

        let val_object = value.as_object().ok_or_else(|| {
            ClaimsResolvingSnafu {
                details: "The value is not an object",
            }
            .build()
        })?;

        for (key, value) in val_object {
            claims.insert(key.clone(), value.clone());
        }

        Ok(claims)
    }

    #[instrument(level = Level::TRACE, skip(issuer_data, holder_data), err(), ret())]
    async fn create_vc<S, K>(
        claims: Claims,
        issuer_data: (&DIDURL, S),
        holder_data: (&DIDURL, K),
        metadata: VCMetadata,
    ) -> Result<Credential>
    where
        S: Signer + Key,
        K: Key,
    {
        trace!(issuer_did_url = ?{issuer_data.0}, holder_did_url = ?{holder_data.0});

        let iss_did = issuer_data.0.did.clone();
        let iss_key_handle = issuer_data.1;

        let pub_key = iss_key_handle.jwk().ok_or_else(|| {
            KeyTypeNotSupportedSnafu {
                type_: "JWK incompatible",
            }
            .build()
        })?;

        let universal_resolver = UniversalResolver::new();
        let verification_method_map = universal_resolver
            .resolve_verification_method(&iss_did)
            .await
            .map_err(|_| {
                CredentialCreationSnafu {
                    details: "Can not find verification method",
                }
                .build()
            })?;

        let resolver = universal_resolver.as_spruce_resolver();

        let mut vc =
            JsonLdAPI::create_credential(metadata, iss_did, holder_data.0.did.clone(), claims);

        let proof_options = ssi::vc::LinkedDataProofOptions {
            verification_method: Some(ssi::vc::URI::String(verification_method_map.id)),
            ..Default::default()
        };

        let mut context_loader = ssi::jsonld::ContextLoader::default();

        let proof_preparation = vc
            .prepare_proof(&pub_key, &proof_options, resolver, &mut context_loader)
            .await
            .map_err(|err| {
                CredentialCreationSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        let sig = JsonLdAPI::sign_proof(&proof_preparation.signing_input, &iss_key_handle).await?;
        let sig_b64 = b64::encode(&sig);

        let proof = proof_preparation
            .proof
            .type_
            .complete(&proof_preparation, &sig_b64)
            .await
            .context(ProofCompletionSnafu)?;

        vc.add_proof(proof);

        Ok(vc)
    }

    #[instrument(level = Level::TRACE, skip(holder_signer, nonce), err(), ret())]
    async fn create_vp<S>(
        credential: &Credential,
        holder_signer: S,
        nonce: &Nonce,
        verifier_id: &str,
        metadata: VPMetadata,
    ) -> Result<Presentation>
    where
        S: Signer + Key,
    {
        let key = holder_signer.jwk().ok_or_else(|| {
            KeyTypeNotSupportedSnafu {
                type_: "JWK incompatible",
            }
            .build()
        })?;

        let universal_resolver = UniversalResolver::new();
        let resolver = universal_resolver.as_spruce_resolver();

        let vc = credential.to_owned();

        let holder_did = match &vc.credential_subject {
            OneOrMany::One(CredentialSubject {
                id: Some(URI::String(did)),
                ..
            }) => did.clone(),
            OneOrMany::Many(_) => {
                return PresentationSnafu {
                    details: "Multiple subjects in the credential",
                }
                .fail()
            }
            _ => {
                return PresentationSnafu {
                    details: "Can not find the holder's DID",
                }
                .fail()
            }
        };

        let verification_method_map = universal_resolver
            .resolve_verification_method(&holder_did)
            .await
            .map_err(|_| {
                PresentationSnafu {
                    details: "Can not find verification method",
                }
                .build()
            })?;

        let mut vp = JsonLdAPI::create_presentation(vc, metadata, holder_did.to_string());

        let proof_options = ssi::vc::LinkedDataProofOptions {
            verification_method: Some(ssi::vc::URI::String(verification_method_map.id)),
            proof_purpose: Some(ssi::vc::ProofPurpose::AssertionMethod),
            ..Default::default()
        };

        let mut context_loader = ssi::jsonld::ContextLoader::default();

        let proof_preparation = vp
            .prepare_proof(&key, &proof_options, resolver, &mut context_loader)
            .await
            .map_err(|err| {
                PresentationSnafu {
                    details: err.to_string(),
                }
                .build()
            })?;

        let sig = JsonLdAPI::sign_proof(&proof_preparation.signing_input, &holder_signer).await?;
        let sig_b64 = b64::encode(&sig);

        let proof = proof_preparation
            .proof
            .type_
            .complete(&proof_preparation, &sig_b64)
            .await
            .context(ProofCompletionSnafu)?;

        vp.add_proof(proof);

        Ok(vp)
    }

    #[instrument(level = Level::TRACE, err(), ret())]
    async fn verify_vc(credential: &Credential, opts: VerifyOptions) -> Result<()> {
        let mut context_loader = ssi::jsonld::ContextLoader::default();
        let universal_resolver = UniversalResolver::new();
        let resolver = universal_resolver.as_spruce_resolver();

        let result = credential.verify(None, resolver, &mut context_loader).await;

        if !result.errors.is_empty() {
            return VerifyingSnafu {
                details: result.errors.join("\n"),
            }
            .fail();
        }

        Ok(())
    }

    #[instrument(level = Level::TRACE, skip(nonce), err(), ret())]
    async fn verify_vp(
        presentation: &Presentation,
        nonce: &Nonce,
        verifier_id: &str,
        _opts: VerifyOptions,
    ) -> Result<Value> {
        let proof_options = ssi::vc::LinkedDataProofOptions {
            proof_purpose: Some(ssi::vc::ProofPurpose::AssertionMethod),
            ..Default::default()
        };

        let universal_resolver = UniversalResolver::new();
        let resolver = universal_resolver.as_spruce_resolver();
        let mut context_loader = ssi::jsonld::ContextLoader::default();

        let result = presentation
            .verify(Some(proof_options), resolver, &mut context_loader)
            .await;

        if !result.errors.is_empty() {
            return VerifyingSnafu {
                details: result.errors.join("\n"),
            }
            .fail();
        }

        let credential = presentation.get_credential()?;

        let credential_json = serde_json::to_value(credential).map_err(|err| {
            VerifyingSnafu {
                details: format!("Can not be serialized to json: {err}"),
            }
            .build()
        })?;

        Ok(credential_json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::nonce::LocalNonceGenerator;
    use crate::kms::KeyType;
    use crate::nonce::NonceGenerator;
    use crate::utils::test_utils::create_did_url_and_key_handle;
    use crate::vc::formats::Error;
    use rstest::rstest;
    use serde_json::json;

    #[tokio::test]
    async fn claims_resolving_works_correctly() {
        let claims = JsonLdAPI::resolve_claims(&json!({
            "key_0": "value_0",
            "key_1": [1, 2, "test"]
        }))
        .unwrap();

        assert_eq!(claims.get("key_0").unwrap(), &json!("value_0"));
        assert_eq!(claims.get("key_1").unwrap(), &json!([1, 2, "test"]));
    }

    #[rstest]
    #[case::p256(KeyType::P256, "EcdsaSecp256r1Signature2019")]
    #[case::ed25519(KeyType::Ed25519, "Ed25519Signature2018")]
    #[tokio::test]
    async fn vc_issuance_and_verification_work_correctly(
        #[case] iss_key_type: KeyType,
        #[case] proof_type: &str,
    ) {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, iss_key_type).await;
        let iss_jwk = iss_kh.clone().jwk().unwrap();

        let metadata = VCMetadata::new(
            vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://w3id.org/citizenship/v1".to_string(),
            ],
            vec!["PermanentResidentCard".to_string()],
        );

        let claims = JsonLdAPI::resolve_claims(&sample_claims()).unwrap();

        let vc = JsonLdAPI::create_vc(
            claims,
            (&iss_did_url, iss_kh.clone()),
            (&hld_did_url, hld_kh.clone()),
            metadata,
        )
        .await
        .unwrap();

        JsonLdAPI::verify_vc(&vc, VerifyOptions {}).await.unwrap();

        let vc = serde_json::to_value(vc)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        let proof = vc.get("proof").unwrap().as_object().unwrap().clone();

        let mut expected_cred_subject = sample_claims();
        expected_cred_subject
            .as_object_mut()
            .unwrap()
            .insert("id".to_string(), Value::String(hld_did_url.did.clone()));

        assert_eq!(
            vc.get("@context").unwrap(),
            &json!([
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/citizenship/v1"
            ])
        );
        assert_eq!(
            vc.get("type").unwrap(),
            &json!(["VerifiableCredential", "PermanentResidentCard"])
        );
        assert_eq!(vc.get("credentialSubject").unwrap(), &expected_cred_subject);
        assert_eq!(vc.get("issuer").unwrap(), &json!(iss_did_url.did.clone()));
        assert!(vc.contains_key("issuanceDate"));
        assert!(vc.contains_key("expirationDate"));
        assert_eq!(proof.get("type").unwrap(), &json!(proof_type.to_string()));
        assert_eq!(
            proof.get("proofPurpose").unwrap(),
            &json!("assertionMethod")
        );
        assert!(proof.contains_key("verificationMethod"));
        assert!(proof.contains_key("created"));
        assert!(proof.contains_key("jws"));
    }

    #[tokio::test]
    async fn vc_issuance_fails_when_claims_can_not_be_expanded() {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let iss_jwk = iss_kh.clone().jwk().unwrap();

        let metadata = VCMetadata::new(
            vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://w3id.org/citizenship/v1".to_string(),
            ],
            vec!["PermanentResidentCard".to_string()],
        );

        let claims = json!({
            "type": ["PermanentResident", "Person"],
            "given_name": "JANE", // given_name is not defined in PermanentResident
            "familyName": "SMITH",
            "gender": "Female",
            "residentSince": "2015-01-01",
            "lprCategory": "C09",
            "lprNumber": "999-999-999",
            "commuterClassification": "C1",
            "birthCountry": "Arcadia",
            "birthDate": "1978-07-17"
        });

        let claims = JsonLdAPI::resolve_claims(&claims).unwrap();

        let vc_issuance_result = JsonLdAPI::create_vc(
            claims,
            (&iss_did_url, iss_kh.clone()),
            (&hld_did_url, hld_kh.clone()),
            metadata,
        )
        .await;

        assert!(matches!(
            vc_issuance_result.err().unwrap(),
            Error::CredentialCreation { .. }
        ));
    }

    #[rstest]
    #[case::p256(KeyType::P256, "EcdsaSecp256r1Signature2019")]
    #[case::ed25519(KeyType::Ed25519, "Ed25519Signature2018")]
    #[tokio::test]
    async fn vp_generation_and_verification_work_correctly(
        #[case] holder_key_type: KeyType,
        #[case] proof_type: &str,
    ) {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, holder_key_type).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let iss_jwk = iss_kh.clone().jwk().unwrap();

        let metadata = VCMetadata::new(
            vec![
                "https://www.w3.org/2018/credentials/v1".to_string(),
                "https://w3id.org/citizenship/v1".to_string(),
            ],
            vec!["PermanentResidentCard".to_string()],
        );

        let claims = JsonLdAPI::resolve_claims(&sample_claims()).unwrap();

        let vc = JsonLdAPI::create_vc(
            claims,
            (&iss_did_url, iss_kh.clone()),
            (&hld_did_url, hld_kh.clone()),
            metadata,
        )
        .await
        .unwrap();

        let nonce = LocalNonceGenerator::default().generate().await.unwrap();

        let presentation = JsonLdAPI::create_vp(
            &vc,
            hld_kh.clone(),
            &nonce,
            "verifier_id",
            VPMetadata::new(),
        )
        .await
        .unwrap();

        JsonLdAPI::verify_vp(
            &presentation,
            &nonce,
            "verifier_id",
            VerifyOptions::default(),
        )
        .await
        .unwrap();

        let vp = serde_json::to_value(presentation)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        let proof = vp.get("proof").unwrap().as_object().unwrap().clone();

        assert_eq!(
            vp.get("@context").unwrap(),
            &json!("https://www.w3.org/2018/credentials/v1")
        );
        assert_eq!(vp.get("type").unwrap(), &json!("VerifiablePresentation"));
        assert_eq!(
            vp.get("verifiableCredential").unwrap(),
            &serde_json::to_value(vc).unwrap()
        );
        assert_eq!(vp.get("holder").unwrap(), &json!(hld_did_url.did.clone()));
        assert_eq!(proof.get("type").unwrap(), &json!(proof_type.to_string()));
        assert_eq!(
            proof.get("proofPurpose").unwrap(),
            &json!("assertionMethod")
        );
        assert!(proof.contains_key("verificationMethod"));
        assert!(proof.contains_key("created"));
        assert!(proof.contains_key("jws"));
    }

    fn sample_claims() -> Value {
        json!({
            "type": ["PermanentResident", "Person"],
            "givenName": "JANE",
            "familyName": "SMITH",
            "gender": "Female",
            "image": "data:image/png;base64,iVBORw0KGgoAA...Jggg==",
            "residentSince": "2015-01-01",
            "lprCategory": "C09",
            "lprNumber": "999-999-999",
            "commuterClassification": "C1",
            "birthCountry": "Arcadia",
            "birthDate": "1978-07-17"
        })
    }
}
