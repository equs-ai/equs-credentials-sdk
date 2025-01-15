use crate::crypto::{Key, Signer};
use crate::did::universal::UniversalResolver;
use crate::did::DIDURL;
use crate::nonce::Nonce;
use crate::vc::claims::{Claim, Claims};
use crate::vc::formats::{
    resolve_verification_method, ClaimsSnafu, CryptoSuiteCreationSnafu, GetExpirationClaim,
    HasClaims, HasCredential, IriBufParsingSnafu, IriRefParsingSnafu, JsonSnafu,
    KeyTypeNotSupportedSnafu, MultipleCredentialsNotSupportedSnafu,
    MultipleSubjectNotSupportedSnafu, NoCredentialSnafu, ParsingSnafu, PresentationSnafu, Result,
    SpruceSigningSnafu, VerifyOptions, VerifyingSnafu, API,
};
use async_trait::async_trait;
use chrono::{FixedOffset, TimeDelta};
use serde::de::IntoDeserializer;
use serde::Deserialize;
use snafu::{ensure, ResultExt};
use ssi::claims::data_integrity::AnyInputSuiteOptions;
use ssi::claims::vc::syntax::IdOr;
use ssi::claims::{MessageSignatureError, SignatureError, VerificationParameters};
use ssi::dids::ssi_json_ld;
use ssi::json_ld::iref::UriBuf;
use ssi::json_ld::syntax::ContextEntry::IriRef;
use ssi::json_ld::{IriBuf, IriRefBuf, CREDENTIALS_V1_CONTEXT, CREDENTIALS_V2_CONTEXT};
use ssi::prelude::{AnyMethod, AnySuite, CryptographicSuite, DataIntegrity, ProofOptions};
use ssi::verification_methods::{LocalSigner, MessageSigner, ReferenceOrOwned};
use ssi::xsd::DateTime;
use ssi::OneOrMany;
use ssi_json_ld::syntax::Context;
use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{instrument, trace, Level};

pub type Credential = ssi::claims::vc::v1::JsonCredential<Claims>;
pub type VC = DataIntegrity<Credential, AnySuite>;
pub type Presentation = ssi::claims::vc::v1::syntax::JsonPresentation<VC>;
pub type VP = DataIntegrity<Presentation, AnySuite>;

const DEFAULT_VC_TYPE: &str = "VerifiableCredential";
const DEFAULT_VP_TYPE: &str = "VerifiablePresentation";

const DEFAULT_CRED_LIFETIME_DAYS: i64 = 5 * 365;

pub type Iri = iref::Iri;

// Metadata
#[derive(Debug)]
pub struct VCMetadata {
    pub contexts: Context,
    pub type_: OneOrMany<String>,
    pub lifetime: TimeDelta,
}

impl VCMetadata {
    #[instrument(level = Level::TRACE, ret())]
    pub fn new(contexts: Vec<IriRefBuf>, types: Vec<String>) -> Result<Self> {
        let mut contexts = contexts;
        let mut types = types;

        let default_ctx_is_provided = contexts.iter().any(|ctx| {
            Some(CREDENTIALS_V1_CONTEXT) == ctx.as_iri()
                || Some(CREDENTIALS_V2_CONTEXT) == ctx.as_iri()
        });

        if !default_ctx_is_provided {
            contexts.push(
                IriRefBuf::new(CREDENTIALS_V1_CONTEXT.to_string()).context(IriRefParsingSnafu)?,
            );
        }

        let contexts = match contexts.len() {
            1 => Context::One(IriRef(contexts[0].to_owned())),
            _ => Context::Many(contexts.into_iter().map(IriRef).collect()),
        };

        if !types.iter().any(|item| item == DEFAULT_VC_TYPE) {
            types.insert(0, DEFAULT_VC_TYPE.to_string());
        }

        let type_ = match types.len() {
            1 => OneOrMany::One(types[0].clone()),
            _ => OneOrMany::Many(types),
        };

        let lifetime = chrono::Duration::days(DEFAULT_CRED_LIFETIME_DAYS);

        Ok(Self {
            contexts,
            type_,
            lifetime,
        })
    }
}

#[derive(Debug)]
pub struct VPMetadata {
    pub contexts: Context,
    pub type_: OneOrMany<String>,
}

impl VPMetadata {
    #[instrument(level = Level::TRACE, ret())]
    pub fn new() -> Result<Self> {
        let context =
            IriRefBuf::new(CREDENTIALS_V1_CONTEXT.to_string()).context(IriRefParsingSnafu)?;
        Ok(Self {
            contexts: Context::One(IriRef(context)),
            type_: OneOrMany::One(DEFAULT_VP_TYPE.to_string()),
        })
    }
}

impl HasClaims<Claims> for VC {
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn parse_claims(&self) -> Result<Claims> {
        if self.credential_subjects.len() != 1 {
            MultipleSubjectNotSupportedSnafu {}.fail()?
        }

        let claims = Claims::try_from(serde_json::to_value(&self.claims).context(JsonSnafu)?)
            .context(ClaimsSnafu)?;

        Ok(claims)
    }
}

impl HasCredential<VC> for VP {
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn get_credential(&self) -> Result<VC> {
        ensure!(
            !self.verifiable_credentials.is_empty(),
            NoCredentialSnafu {}
        );

        ensure!(
            self.verifiable_credentials.len() == 1,
            MultipleCredentialsNotSupportedSnafu {}
        );

        Ok(self.verifiable_credentials[0].to_owned())
    }
}

pub struct JsonLdAPI;
struct JsonLdSigner<S: Signer + Key> {
    signer: Arc<S>,
}

impl JsonLdAPI {
    #[instrument(level = Level::TRACE, ret())]
    fn create_credential(
        metadata: VCMetadata,
        iss_did: &str,
        holder_did: &str,
        mut claims: Claims,
    ) -> Result<Credential> {
        claims.insert("id".to_string(), Claim::String(holder_did.to_string()));

        let now = chrono::Local::now().to_utc();
        let lifetime = FixedOffset::from_str(&metadata.lifetime.to_string()).ok();
        let exp_date =
            JsonLdAPI::get_expiration_claim(&claims).unwrap_or((now + metadata.lifetime).into());
        let iss_date = now.into();

        let issuer = IdOr::Id(UriBuf::from_str(iss_did).map_err(|e| {
            ParsingSnafu {
                details: format!("Could not parse issuer did as uri buf {e}"),
            }
            .build()
        })?);

        let (context, types) = Self::resolve_context_and_types(metadata.contexts, metadata.type_)?;

        Ok(Credential {
            context,
            types,
            issuer,
            credential_subjects: ssi::claims::vc::syntax::NonEmptyVec::new(claims),
            issuance_date: Some(iss_date),
            expiration_date: Some(exp_date),

            additional_properties: Default::default(),

            id: None,
            credential_status: vec![],
            terms_of_use: vec![],
            evidence: vec![],
            credential_schema: vec![],
            refresh_services: vec![],
        })
    }

    #[instrument(level = Level::TRACE, ret())]
    fn create_presentation(
        vc: VC,
        metadata: VPMetadata,
        holder_did: String,
    ) -> Result<Presentation> {
        let (context, types) = Self::resolve_context_and_types(metadata.contexts, metadata.type_)?;

        Ok(Presentation {
            context,
            verifiable_credentials: vec![vc],
            types,

            holder: Some(UriBuf::new(holder_did.into_bytes()).map_err(|e| {
                ParsingSnafu {
                    details: "Could not parse did into uri buf",
                }
                .build()
            })?),

            id: None,
            additional_properties: Default::default(),
        })
    }

    pub fn resolve_context_and_types<C, T>(
        contexts: Context,
        types: OneOrMany<String>,
    ) -> Result<(
        ssi::claims::vc::syntax::Context<C>,
        ssi::claims::vc::syntax::Types<T>,
    )>
    where
        C: ssi::claims::vc::syntax::RequiredContext,
        T: ssi::claims::vc::syntax::RequiredType,
    {
        let mut context = ssi::claims::vc::syntax::Context::default();
        match contexts {
            Context::One(value) => {
                context.insert(value);
            }
            Context::Many(value) => context.extend(value),
        };

        let types = ssi::claims::vc::syntax::Types::deserialize(
            serde_json::to_value(types)
                .context(JsonSnafu)?
                .into_deserializer(),
        )
        .context(JsonSnafu)?;

        Ok((context, types))
    }
}

impl GetExpirationClaim<Claims, DateTime> for JsonLdAPI {
    fn get_expiration_claim(claims: &Claims) -> Option<DateTime> {
        claims
            .get("expirationDate")
            .and_then(|v| v.to_owned().try_into().ok())
            .and_then(|v| serde_json::from_value(v).ok())
    }
}

#[async_trait]
impl API<Claims, VC, VP, VCMetadata, VPMetadata, ()> for JsonLdAPI {
    #[instrument(level = Level::TRACE, skip(issuer_data, holder_data), err(), ret())]
    async fn create_vc<S, K>(
        claims: Claims,
        issuer_data: (&DIDURL, S),
        holder_data: (&DIDURL, K),
        metadata: VCMetadata,
    ) -> Result<VC>
    where
        S: Signer + Key,
        K: Key,
    {
        trace!(issuer_did_url = ?{issuer_data.0}, holder_did_url = ?{holder_data.0});

        let iss_did = issuer_data.0.did();
        let pub_key = issuer_data.1.jwk().ok_or_else(|| {
            KeyTypeNotSupportedSnafu {
                type_: "JWK incompatible",
            }
            .build()
        })?;

        let resolver = UniversalResolver::default();

        let vc = JsonLdAPI::create_credential(
            metadata,
            iss_did.as_str(),
            holder_data.0.did().as_str(),
            claims,
        )?;
        let signer = LocalSigner(JsonLdSigner {
            signer: Arc::new(issuer_data.1),
        });

        let verification_method = resolve_verification_method(iss_did).await?;
        let verification_method_id =
            IriBuf::from_str(&verification_method.id).context(IriBufParsingSnafu)?;

        let options = ProofOptions::from_method_and_options(
            ReferenceOrOwned::Reference(verification_method_id.clone()),
            Default::default(),
        );

        let suite =
            AnySuite::pick(&pub_key, options.verification_method.as_ref()).ok_or_else(|| {
                CryptoSuiteCreationSnafu {
                    details: format!(
                        "Could not pick crypto suite for verification method = {}",
                        verification_method_id
                    ),
                }
                .build()
            })?;

        suite
            .sign(vc.clone(), resolver, signer, options)
            .await
            .context(SpruceSigningSnafu)
    }

    #[instrument(level = Level::TRACE, skip(holder_signer, nonce), err(), ret())]
    async fn create_vp<S>(
        credential: &VC,
        holder_signer: S,
        nonce: &Nonce,
        verifier_id: &str,
        metadata: VPMetadata,
    ) -> Result<VP>
    where
        S: Signer + Key,
    {
        let key = holder_signer.jwk().ok_or_else(|| {
            KeyTypeNotSupportedSnafu {
                type_: "JWK incompatible",
            }
            .build()
        })?;

        let resolver = UniversalResolver::default();

        let holder_did = match credential.credential_subjects.len() {
            1 => match credential
                .credential_subjects
                .first()
                .map(|c| c.get("id").to_owned())
            {
                Some(Some(Claim::String(id))) => id,
                _ => {
                    return PresentationSnafu {
                        details: "Could not parse subject 'id' of vc",
                    }
                    .fail()?
                }
            },
            _ => {
                return PresentationSnafu {
                    details: "Multiple subjects in the credential is not supported",
                }
                .fail()?
            }
        };

        let vp = JsonLdAPI::create_presentation(
            credential.to_owned(),
            metadata,
            holder_did.to_string(),
        )?;

        let resolver = UniversalResolver::default();
        let verifier = VerificationParameters::from_resolver(&resolver);

        let signer = LocalSigner(JsonLdSigner {
            signer: Arc::new(holder_signer),
        });

        let verification_method = resolve_verification_method(holder_did).await?;
        let verification_method_id =
            IriBuf::from_str(&verification_method.id).context(IriBufParsingSnafu)?;

        let mut params = ProofOptions::from_method_and_options(
            ReferenceOrOwned::Reference(verification_method_id.clone()),
            AnyInputSuiteOptions::new(),
        );

        params.nonce = Some(nonce.secret().to_owned());

        let suite = AnySuite::pick(&key, params.verification_method.as_ref()).ok_or_else(|| {
            CryptoSuiteCreationSnafu {
                details: format!(
                    "Could not pick crypto suite for verification method = {}",
                    verification_method_id
                ),
            }
            .build()
        })?;
        suite
            .sign(vp, resolver, &signer, params)
            .await
            .context(SpruceSigningSnafu)
    }

    #[instrument(level = Level::TRACE, err(), ret())]
    async fn verify_vc(credential: &VC, opts: VerifyOptions) -> Result<()> {
        let resolver = UniversalResolver::default();
        let verifier = VerificationParameters::from_resolver(resolver);

        let result = credential
            .verify(&verifier)
            .await
            .map_err(|e| {
                VerifyingSnafu {
                    details: e.to_string(),
                }
                .build()
            })?
            .map_err(|e| {
                VerifyingSnafu {
                    details: e.to_string(),
                }
                .build()
            })?;

        Ok(())
    }

    #[instrument(level = Level::TRACE, skip(nonce), err(), ret())]
    async fn verify_vp(
        presentation: &VP,
        nonce: &Nonce,
        verifier_id: &str,
        _opts: VerifyOptions,
    ) -> Result<()> {
        let resolver = UniversalResolver::default();

        let verifier = VerificationParameters::from_resolver(resolver);
        presentation
            .verify(verifier)
            .await
            .map_err(|e| {
                VerifyingSnafu {
                    details: e.to_string(),
                }
                .build()
            })?
            .map_err(|e| {
                VerifyingSnafu {
                    details: e.to_string(),
                }
                .build()
            })?;

        Ok(())
    }
}

impl<S: Signer + Key> MessageSigner<ssi::crypto::Algorithm> for JsonLdSigner<S> {
    async fn sign(
        self,
        algorithm: ssi::crypto::AlgorithmInstance,
        message: &[u8],
    ) -> std::result::Result<Vec<u8>, MessageSignatureError> {
        match algorithm {
            ssi::crypto::AlgorithmInstance::EdDSA | ssi::crypto::AlgorithmInstance::ES256 => self
                .signer
                .sign(message)
                .await
                .map_err(|e| MessageSignatureError::SignatureFailed(e.to_string())),
            _ => Err(MessageSignatureError::UnsupportedAlgorithm(format!(
                "{}",
                algorithm.algorithm()
            ))),
        }
    }
}

impl<S: Signer + Key> ssi::verification_methods::Signer<AnyMethod> for JsonLdSigner<S> {
    type MessageSigner = JsonLdSigner<S>;

    async fn for_method(
        &self,
        method: Cow<'_, AnyMethod>,
    ) -> std::result::Result<Option<Self::MessageSigner>, SignatureError> {
        Ok(Some(JsonLdSigner {
            signer: self.signer.clone(),
        }))
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
    use crate::utils::test_utils::{failed_signer_key, no_jwk_key};
    use crate::vc::claims::Claim;
    use crate::vc::formats::Error;
    use rstest::rstest;
    use serde_json::{json, Value};

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

        let metadata = VCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/2018/credentials/v1").unwrap(),
                IriRefBuf::from_str("https://w3id.org/citizenship/v1").unwrap(),
            ],
            vec!["PermanentResidentCard".to_string()],
        )
        .unwrap();

        let vc = JsonLdAPI::create_vc(
            sample_claims(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh),
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
        expected_cred_subject.insert(
            "id".to_string(),
            Claim::String(hld_did_url.did().to_string()),
        );

        let expected_cred_subject: Value = expected_cred_subject.try_into().unwrap();
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
        assert_eq!(
            vc.get("issuer").unwrap(),
            &json!(iss_did_url.did().to_string())
        );
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
    async fn issuance_fails_in_case_of_signer_error() {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let metadata = VCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/2018/credentials/v1").unwrap(),
                IriRefBuf::from_str("https://w3id.org/citizenship/v1").unwrap(),
            ],
            vec!["PermanentResidentCard".to_string()],
        )
        .unwrap();

        let result = JsonLdAPI::create_vc(
            sample_claims(),
            (&iss_did_url, failed_signer_key(iss_kh)),
            (&hld_did_url, hld_kh),
            metadata,
        )
        .await;

        assert!(matches!(
            result.err().unwrap(),
            crate::vc::formats::Error::SpruceSigning { .. }
        ));
    }

    #[tokio::test]
    async fn issuance_fails_in_case_of_jwk_error() {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let metadata = VCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/2018/credentials/v1").unwrap(),
                IriRefBuf::from_str("https://w3id.org/citizenship/v1").unwrap(),
            ],
            vec!["PermanentResidentCard".to_string()],
        )
        .unwrap();

        let result = JsonLdAPI::create_vc(
            sample_claims(),
            (&iss_did_url, no_jwk_key()),
            (&hld_did_url, hld_kh),
            metadata,
        )
        .await;

        assert!(matches!(
            result.err().unwrap(),
            crate::vc::formats::Error::KeyTypeNotSupported { .. }
        ));
    }

    #[tokio::test]
    async fn vc_issuance_fails_when_claims_can_not_be_expanded() {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let metadata = VCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/2018/credentials/v1").unwrap(),
                IriRefBuf::from_str("https://w3id.org/citizenship/v1").unwrap(),
            ],
            vec!["PermanentResidentCard".to_string()],
        )
        .unwrap();

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
        })
        .try_into()
        .unwrap();

        let vc_issuance_result = JsonLdAPI::create_vc(
            claims,
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh),
            metadata,
        )
        .await;

        assert!(vc_issuance_result.err().unwrap().to_string().contains(
            "JSON-LD expansion failed: expansion error: Key `given_name` expansion failed"
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

        let metadata = VCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/2018/credentials/v1").unwrap(),
                IriRefBuf::from_str("https://w3id.org/citizenship/v1").unwrap(),
            ],
            vec!["PermanentResidentCard".to_string()],
        )
        .unwrap();

        let vc = JsonLdAPI::create_vc(
            sample_claims(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh.clone()),
            metadata,
        )
        .await
        .unwrap();

        let nonce = LocalNonceGenerator::default().generate().await.unwrap();

        let presentation = JsonLdAPI::create_vp(
            &vc,
            hld_kh,
            &nonce,
            "verifier_id",
            VPMetadata::new().unwrap(),
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
            &json!(["https://www.w3.org/2018/credentials/v1"])
        );
        assert_eq!(vp.get("type").unwrap(), &json!(["VerifiablePresentation"]));
        assert_eq!(
            vp.get("verifiableCredential").unwrap(),
            &serde_json::to_value(vc).unwrap()
        );
        assert_eq!(
            vp.get("holder").unwrap(),
            &Value::String(hld_did_url.did().to_string())
        );
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
    async fn presentation_fails_in_case_of_signer_error() {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let metadata = VCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/2018/credentials/v1").unwrap(),
                IriRefBuf::from_str("https://w3id.org/citizenship/v1").unwrap(),
            ],
            vec!["PermanentResidentCard".to_string()],
        )
        .unwrap();

        let vc = JsonLdAPI::create_vc(
            sample_claims(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh.clone()),
            metadata,
        )
        .await
        .unwrap();

        let nonce = LocalNonceGenerator::default().generate().await.unwrap();

        let result = JsonLdAPI::create_vp(
            &vc,
            failed_signer_key(hld_kh),
            &nonce,
            "verifier_id",
            VPMetadata::new().unwrap(),
        )
        .await;

        assert!(matches!(result.err().unwrap(), Error::SpruceSigning { .. }));
    }

    #[tokio::test]
    async fn presentation_fails_in_case_of_jwk_error() {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let metadata = VCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/2018/credentials/v1").unwrap(),
                IriRefBuf::from_str("https://w3id.org/citizenship/v1").unwrap(),
            ],
            vec!["PermanentResidentCard".to_string()],
        )
        .unwrap();

        let vc = JsonLdAPI::create_vc(
            sample_claims(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh),
            metadata,
        )
        .await
        .unwrap();

        let nonce = LocalNonceGenerator::default().generate().await.unwrap();

        let result = JsonLdAPI::create_vp(
            &vc,
            no_jwk_key(),
            &nonce,
            "verifier_id",
            VPMetadata::new().unwrap(),
        )
        .await;

        assert!(matches!(
            result.err().unwrap(),
            crate::vc::formats::Error::KeyTypeNotSupported { .. }
        ));
    }

    fn sample_claims() -> Claims {
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
        .try_into()
        .unwrap()
    }
}
