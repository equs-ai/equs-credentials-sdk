use crate::crypto::{Alg, Key, Signer, SigningOptions};
use crate::did::universal::UniversalResolver;
use crate::did::{DIDResolver, DIDURL};
use crate::vc::claims::{Claim, Claims};
use crate::vc::core::{HolderBinder, PresentationInput, PresentationRestrictionValue};
use crate::vc::formats::{
    API, ClaimsSnafu, CredentialCreationSnafu, CryptoSuiteCreationSnafu, DIDSnafu,
    GetDateTimeClaim, HasClaims, HasCredential, IriBufParsingSnafu, IriRefParsingSnafu, IsExpired,
    JsonPointerParsingSnafu, JsonSnafu, KeyTypeNotSupportedSnafu,
    MultipleCredentialsNotSupportedSnafu, MultipleSubjectNotSupportedSnafu, NoCredentialSnafu,
    ParsingSnafu, PresentationSnafu, Result, SigningSnafu, SpruceSigningSnafu, VerifyOptions,
    VerifyingSnafu,
};
use crate::vc::oid4vci::credential_issuer_identifier::CredentialIssuerIdentifier;
use async_trait::async_trait;
use chrono::Utc;
use serde::Deserialize;
use serde::de::{DeserializeOwned, IntoDeserializer};
use snafu::{ResultExt, ensure};
use ssi::claims::data_integrity::{AnyInputSuiteOptions, AnySelectionOptions, AnySignatureOptions};
use ssi::claims::vc::AnySpecializedJsonCredential;
use ssi::claims::vc::syntax::IdOr;
use ssi::claims::vc::v2::CREDENTIALS_V2_CONTEXT_IRI;
use ssi::claims::{
    MessageSignatureError, SignatureError, VerifiableClaims, VerificationParameters,
};
use ssi::dids::ssi_json_ld;
use ssi::json_ld::iref::UriBuf;
use ssi::json_ld::syntax::ContextEntry::IriRef;
use ssi::json_ld::{
    CREDENTIALS_V1_CONTEXT, CREDENTIALS_V2_CONTEXT, IriBuf, IriRefBuf, JsonLdObject,
};
use ssi::prelude::{
    AnyJsonPresentation, AnyMethod, AnySuite, CryptographicSuite, DataIntegrity, ProofOptions,
};
use ssi::verification_methods::{LocalSigner, MessageSigner, ReferenceOrOwned};
use ssi::xsd::{DateTime, DateTimeStamp};
use ssi::{JsonPointerBuf, OneOrMany};
use ssi_json_ld::syntax::Context;
use std::borrow::Cow;
use std::str::FromStr;
use std::sync::Arc;
use time::Duration;
use tracing::{Level, instrument, trace};

pub type Credential = AnySpecializedJsonCredential<Claims>;
pub type VC = DataIntegrity<Credential, AnySuite>;
pub type Presentation = AnyJsonPresentation<
    DataIntegrity<ssi::claims::vc::v1::JsonCredential<Claims>, AnySuite>,
    DataIntegrity<ssi::claims::vc::v2::JsonCredential<Claims>, AnySuite>,
>;
pub type VP = DataIntegrity<Presentation, AnySuite>;

const DEFAULT_VC_TYPE: &str = "VerifiableCredential";
const DEFAULT_VP_TYPE: &str = "VerifiablePresentation";
pub type Iri = iref::Iri;

// Metadata
#[derive(Debug)]
pub struct VCMetadata {
    pub contexts: Context,
    pub type_: OneOrMany<String>,
    pub lifetime: Option<Duration>,
    pub credential_id: Option<UriBuf>,
    pub mandatory_claims: Option<Vec<JsonPointerBuf>>,
}

impl VCMetadata {
    #[instrument(level = Level::TRACE, ret())]
    pub fn new(
        contexts: Vec<IriRefBuf>,
        types: Vec<String>,
        lifetime: Option<Duration>,
    ) -> Result<Self> {
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

        Ok(Self {
            contexts,
            type_,
            lifetime,
            mandatory_claims: None,
            credential_id: None,
        })
    }

    pub fn set_credential_id(&mut self, credential_id: UriBuf) {
        self.credential_id = Some(credential_id);
    }
}

#[derive(Debug)]
pub struct VPMetadata {
    pub contexts: Context,
    pub type_: OneOrMany<String>,
    pub disclosures: Vec<JsonPointerBuf>,
    pub holder_binder: Option<HolderBinder>,
}

impl VPMetadata {
    #[instrument(level = Level::TRACE, ret())]
    pub fn new(vc: &VC, holder_binder: Option<HolderBinder>) -> Result<Self> {
        let is_v2 = vc.json_ld_context().iter().any(|c| {
            c.as_slice()
                .contains(&IriRef(CREDENTIALS_V2_CONTEXT_IRI.to_owned().into()))
        });

        let (ctx_iri, types) = if is_v2 {
            (
                CREDENTIALS_V2_CONTEXT,
                OneOrMany::One(DEFAULT_VP_TYPE.to_string()),
            )
        } else {
            (
                CREDENTIALS_V1_CONTEXT,
                OneOrMany::Many(vec![DEFAULT_VP_TYPE.to_string()]),
            )
        };

        let context = IriRefBuf::new(ctx_iri.to_string()).context(IriRefParsingSnafu)?;
        Ok(Self {
            contexts: Context::One(IriRef(context)),
            type_: types,
            disclosures: vec![],
            holder_binder,
        })
    }

    pub fn set_disclosures(&mut self, disclosures: Vec<JsonPointerBuf>) {
        self.disclosures = disclosures;
    }
    pub fn from_presentation_input(
        vc: &VC,
        presentation_input: &PresentationInput,
        holder_binder: Option<HolderBinder>,
    ) -> Result<Self> {
        let disclosures = if JsonLdAPI::is_bbs_plus_signed(vc) {
            JsonLdAPI::resolve_disclosures_for_bbs_plus_signed_vc(presentation_input)?
        } else {
            vec![]
        };

        let mut metadata = Self::new(vc, holder_binder)?;
        metadata.set_disclosures(disclosures);

        Ok(metadata)
    }
}

impl HasClaims<Claims> for VC {
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn parse_claims(&self) -> Result<Claims> {
        let cred_sub_len = match &self.claims {
            Credential::V1(crd) => crd.credential_subjects.len(),
            Credential::V2(crd) => crd.credential_subjects.len(),
        };
        if cred_sub_len != 1 {
            MultipleSubjectNotSupportedSnafu {}.fail()?
        }

        let claims = Claims::try_from(serde_json::to_value(&self.claims).context(JsonSnafu)?)
            .context(ClaimsSnafu)?;

        Ok(claims)
    }

    #[instrument(level = Level::TRACE, ret)]
    fn has_type(&self, type_: PresentationRestrictionValue) -> Result<bool> {
        let claims = self.parse_claims()?;

        let mut has_type = false;
        if let Some(Claim::Array(claims)) = claims.get("$.type") {
            for claim in claims {
                let value = serde_json::to_value(claim).context(JsonSnafu)?;
                let result = type_
                    .validate_claim_for_string_or_pattern(value)
                    .map_err(|e| {
                        ParsingSnafu {
                            details: e.to_string(),
                        }
                        .build()
                    })?;
                if result {
                    has_type = true;
                    break;
                }
            }
        }
        Ok(has_type)
    }
}

impl HasCredential<VC> for VP {
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    fn get_credential(&self) -> Result<VC> {
        let vc = match &self.claims {
            Presentation::V1(pr) => {
                ensure!(!pr.verifiable_credentials.is_empty(), NoCredentialSnafu {});
                ensure!(
                    pr.verifiable_credentials.len() == 1,
                    MultipleCredentialsNotSupportedSnafu {}
                );

                VC::new(
                    Credential::V1(pr.verifiable_credentials[0].claims().to_owned()),
                    pr.verifiable_credentials[0].proofs.to_owned(),
                )
            }
            Presentation::V2(pr) => {
                ensure!(!pr.verifiable_credentials.is_empty(), NoCredentialSnafu {});
                ensure!(
                    pr.verifiable_credentials.len() == 1,
                    MultipleCredentialsNotSupportedSnafu {}
                );

                VC::new(
                    Credential::V2(pr.verifiable_credentials[0].claims().to_owned()),
                    pr.verifiable_credentials[0].proofs.to_owned(),
                )
            }
        };

        Ok(vc)
    }
}

#[derive(Default, Debug)]
pub struct JsonLdAPI;

struct JsonLdSigner<S: Signer + Key> {
    signer: Arc<S>,
}

impl JsonLdAPI {
    #[instrument(level = Level::TRACE, ret())]
    pub fn create_credential(
        metadata: &VCMetadata,
        iss_did: &str,
        holder_did: Option<&str>,
        mut claims: Claims,
    ) -> Result<Credential> {
        if let Some(did) = holder_did {
            claims.insert("id".to_string(), Claim::String(did.to_string()));
        }

        let now = chrono::Local::now().to_utc();

        let issuer = IdOr::Id(UriBuf::from_str(iss_did).map_err(|e| {
            ParsingSnafu {
                details: format!("Could not parse issuer did as uri buf {e}"),
            }
            .build()
        })?);

        let is_v2 = metadata
            .contexts
            .iter()
            .any(|c| c == &IriRef(CREDENTIALS_V2_CONTEXT_IRI.to_owned().into()));

        let vc = if is_v2 {
            let (context, types) =
                Self::resolve_context_and_types(&metadata.contexts, &metadata.type_)?;

            let exp_date = JsonLdAPI::get_date_time_claim("validUntil", &claims)
                .or(Self::calculate_expiration_date(now, metadata.lifetime));

            AnySpecializedJsonCredential::V2(
                ssi::claims::vc::v2::syntax::SpecializedJsonCredential {
                    context,
                    types,
                    issuer,
                    credential_subjects: ssi::claims::vc::syntax::NonEmptyVec::new(claims),
                    id: metadata.credential_id.to_owned(),
                    valid_from: Some(now.into()),
                    valid_until: exp_date.map(|exp| exp.date_time.and_utc().into()),
                    credential_status: vec![],
                    terms_of_use: vec![],
                    evidence: vec![],
                    credential_schema: vec![],
                    refresh_services: vec![],
                    extra_properties: Default::default(),
                },
            )
        } else {
            let (context, types) =
                Self::resolve_context_and_types(&metadata.contexts, &metadata.type_)?;
            let exp_date = JsonLdAPI::get_date_time_claim("expirationDate", &claims)
                .or(Self::calculate_expiration_date(now, metadata.lifetime));

            AnySpecializedJsonCredential::V1(
                ssi::claims::vc::v1::syntax::SpecializedJsonCredential {
                    context,
                    types,
                    issuer,
                    credential_subjects: ssi::claims::vc::syntax::NonEmptyVec::new(claims),
                    id: metadata.credential_id.to_owned(),
                    issuance_date: Some(now.into()),
                    expiration_date: exp_date,
                    credential_status: vec![],
                    terms_of_use: vec![],
                    evidence: vec![],
                    credential_schema: vec![],
                    refresh_services: vec![],
                    additional_properties: Default::default(),
                },
            )
        };

        Ok(vc)
    }

    fn calculate_expiration_date(
        now: chrono::DateTime<Utc>,
        lifetime: Option<Duration>,
    ) -> Option<DateTime> {
        lifetime
            .map(|lifetime| lifetime.whole_nanoseconds().try_into().unwrap_or(i64::MAX))
            .map(|lifetime| (now + chrono::Duration::nanoseconds(lifetime)).into())
    }

    pub async fn sign_credential<S>(
        vc: Credential,
        issuer_data: (&DIDURL, S),
        mandatory_claims: Option<Vec<JsonPointerBuf>>,
        did_resolver: UniversalResolver,
    ) -> Result<VC>
    where
        S: Signer + Key,
    {
        let singing_alg = issuer_data.1.alg().to_owned();
        let pub_key = issuer_data.1.jwk().ok_or_else(|| {
            KeyTypeNotSupportedSnafu {
                type_: "JWK incompatible",
            }
            .build()
        })?;
        let signer = LocalSigner(JsonLdSigner {
            signer: Arc::new(issuer_data.1),
        });

        let (suite, sign_opts) = match &vc {
            Credential::V2(vc_v2) => {
                Self::select_crypto_suite_for_v2_signing(&singing_alg, mandatory_claims)?
            }
            _ => {
                let suite = AnySuite::pick(&pub_key, None).ok_or_else(|| {
                    CryptoSuiteCreationSnafu {
                        details: "Could not pick crypto suite to sign json-ld v1 credential",
                    }
                    .build()
                })?;

                (suite, Default::default())
            }
        };

        suite
            .sign_with(
                ssi::claims::SignatureEnvironment::default(),
                vc,
                &did_resolver,
                signer,
                ProofOptions::from_method(issuer_data.0.as_iri().into()),
                sign_opts,
            )
            .await
            .context(SpruceSigningSnafu)
    }

    #[instrument(level = Level::TRACE, ret())]
    fn create_presentation(
        vc: VC,
        metadata: &VPMetadata,
        holder_did: &str,
    ) -> Result<Presentation> {
        let vc = match vc.claims {
            Credential::V1(v1_vc) => {
                let (context, types) =
                    Self::resolve_context_and_types(&metadata.contexts, &metadata.type_)?;
                let holder_id = UriBuf::new(holder_did.to_string().into_bytes()).map_err(|e| {
                    ParsingSnafu {
                        details: "Could not parse did into uri buf",
                    }
                    .build()
                })?;

                let v1_vp = ssi::claims::vc::v1::syntax::JsonPresentation {
                    context,
                    types,
                    holder: Some(holder_id),
                    verifiable_credentials: vec![DataIntegrity::new(v1_vc, vc.proofs)],
                    id: None,
                    additional_properties: Default::default(),
                };

                Presentation::V1(v1_vp)
            }
            Credential::V2(v2_vc) => {
                let (context, types) =
                    Self::resolve_context_and_types(&metadata.contexts, &metadata.type_)?;
                let holder_id = IdOr::Id(UriBuf::from_str(holder_did).map_err(|e| {
                    ParsingSnafu {
                        details: "Could not parse did into uri buf",
                    }
                    .build()
                })?);

                let v2_vp = ssi::claims::vc::v2::syntax::JsonPresentation {
                    context,
                    types,
                    holders: vec![holder_id],
                    verifiable_credentials: vec![DataIntegrity::new(v2_vc, vc.proofs)],
                    id: None,
                    additional_properties: Default::default(),
                };

                Presentation::V2(v2_vp)
            }
        };

        Ok(vc)
    }

    #[instrument(level = Level::TRACE, skip(did_resolver), err(), ret())]
    async fn create_vp_for_bbs_plus_signed_vc(
        vc: VC,
        metadata: VPMetadata,
        holder_did: &str,
        did_resolver: UniversalResolver,
    ) -> Result<VP> {
        let (context, types) =
            Self::resolve_context_and_types(&metadata.contexts, &metadata.type_)?;
        let holder_id = IdOr::Id(UriBuf::from_str(holder_did).map_err(|e| {
            ParsingSnafu {
                details: "Could not parse did into uri buf",
            }
            .build()
        })?);

        let verifier = VerificationParameters::from_resolver(did_resolver.clone());
        let mut selection_opts = AnySelectionOptions::default();
        selection_opts.selective_pointers = metadata.disclosures;

        let derived = Self::create_derived_vc_from_base(&vc, &verifier, selection_opts).await?;

        let vp = ssi::claims::vc::v2::syntax::JsonPresentation {
            context,
            types,
            holders: vec![holder_id],
            verifiable_credentials: vec![derived],
            id: None,
            additional_properties: Default::default(),
        };

        Ok(DataIntegrity::new(Presentation::V2(vp), Default::default()))
    }

    async fn create_derived_vc_from_base<T: DeserializeOwned>(
        vc: &VC,
        verifier: &VerificationParameters<UniversalResolver>,
        selection_opts: AnySelectionOptions,
    ) -> Result<DataIntegrity<T, AnySuite>> {
        let derived = vc
            .select(&verifier, selection_opts)
            .await
            .map_err(|e| {
                VerifyingSnafu {
                    details: format!("Could not select claims to disclose: {e}"),
                }
                .build()
            })?
            .map(|object| {
                ssi::json_ld::syntax::from_value::<T>(ssi_json_ld::syntax::Value::Object(object))
            });

        let derived = match derived.claims {
            Ok(claims) => DataIntegrity::new(claims, derived.proofs),
            Err(e) => VerifyingSnafu {
                details: format!("Could not deserialize derived vc into json-ld v2 format: {e}"),
            }
            .fail()?,
        };

        Ok(derived)
    }

    pub fn resolve_context_and_types<C, T>(
        contexts: &Context,
        types: &OneOrMany<String>,
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
                context.insert(value.to_owned());
            }
            Context::Many(value) => context.extend(value.to_owned()),
        };

        let types = ssi::claims::vc::syntax::Types::deserialize(
            serde_json::to_value(types)
                .context(JsonSnafu)?
                .into_deserializer(),
        )
        .context(JsonSnafu)?;

        Ok((context, types))
    }

    pub fn resolve_disclosures_for_bbs_plus_signed_vc(
        presentation_input: &PresentationInput,
    ) -> Result<Vec<JsonPointerBuf>> {
        let mut disclosures = vec![];
        for r in presentation_input.restrictions.iter() {
            //TODO: Implement cases when restriction has a value or its an optional field
            for f in r.fields.iter() {
                let json_pointer = if serde_json_path::JsonPath::parse(f).is_ok() {
                    crate::utils::json::path_to_json_pointer(f).map_err(|e| {
                        ParsingSnafu {
                            details: format!("could not convert json_path to json_pointer: {e}"),
                        }
                        .build()
                    })?
                } else {
                    JsonPointerBuf::from_str(f).context(JsonPointerParsingSnafu)?
                };

                disclosures.push(json_pointer);
            }
        }

        Ok(disclosures)
    }

    #[instrument(level = Level::TRACE, err(), ret())]
    fn select_crypto_suite_for_v2_signing(
        singing_alg: &Alg,
        mandatory_claims: Option<Vec<JsonPointerBuf>>,
    ) -> Result<(AnySuite, AnySignatureOptions)> {
        let (suite, sign_opts) = match singing_alg {
            Alg::ES256K => {
                SigningSnafu {
                    details: "Unsupported key alg = 'ES256K' to create Data integrity proof with 'secp256k1` signature",
                }
                    .fail()?
            }
            Alg::ES256 => (AnySuite::EcdsaRdfc2019, Default::default()),
            Alg::EdDSA => (AnySuite::EdDsaRdfc2022, Default::default()),
            Alg::BBS => {
                let mut sign_opts = AnySignatureOptions::default();
                if let Some(mp) = mandatory_claims {
                    sign_opts.mandatory_pointers = mp;
                }

                (AnySuite::Bbs2023, sign_opts)
            }
        };

        Ok((suite, sign_opts))
    }

    #[instrument(level = Level::TRACE, err(), ret())]
    fn prepare_bbs_plus_selection_opts(opts: VerifyOptions) -> Result<AnySelectionOptions> {
        let mut selection = ssi::claims::data_integrity::AnySelectionOptions::default();
        let selective_claims = opts.selective_claims.ok_or_else(|| {
            VerifyingSnafu {
                details: "Selective claims are required to verify bbs+ signed vc".to_string(),
            }
            .build()
        })?;

        let mut selective_pointers = vec![];
        for sc in selective_claims {
            let sp = sc.parse().map_err(|e| {
                VerifyingSnafu {
                    details: format!("Could not parse selective claims as json pointer: {e}"),
                }
                .build()
            })?;
            selective_pointers.push(sp);
        }

        selection.selective_pointers = selective_pointers;
        Ok(selection)
    }

    fn is_bbs_plus_signed(vc: &VC) -> bool {
        vc.proofs.iter().any(|s| s.type_ == AnySuite::Bbs2023)
    }

    #[instrument(level = Level::TRACE, ret())]
    pub(crate) fn extract_issuer_identifier(
        credential: &VC,
    ) -> Result<Option<CredentialIssuerIdentifier>> {
        let issuer_claim = match &credential.claims {
            Credential::V1(claims) => &claims.issuer,
            Credential::V2(claims) => &claims.issuer,
        };
        let issuer_id = match issuer_claim {
            IdOr::Id(id) => id,
            IdOr::NotId(obj) => &obj.id,
        };
        Ok(Some(CredentialIssuerIdentifier::from(
            issuer_id.to_string(),
        )))
    }
}

impl GetDateTimeClaim<Claims, DateTime> for JsonLdAPI {
    fn get_date_time_claim(exp_key: &str, claims: &Claims) -> Option<DateTime> {
        claims
            .get(exp_key)
            .and_then(|v| v.to_owned().try_into().ok())
            .and_then(|v| serde_json::from_value(v).ok())
    }
}

impl IsExpired<VC> for JsonLdAPI {
    fn is_expired(credential: &VC) -> Result<bool> {
        Ok(match &credential.claims {
            Credential::V1(cred) => cred
                .expiration_date
                .is_some_and(|exp_time| DateTime::now() > exp_time),
            Credential::V2(cred) => cred
                .valid_until
                .is_some_and(|exp_time| DateTimeStamp::now() > exp_time),
        })
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl API<Claims, VC, VP, VCMetadata, VPMetadata, ()> for JsonLdAPI {
    #[instrument(level = Level::TRACE, skip(issuer_data, holder_data, did_resolver), err(), ret())]
    async fn create_vc<S, K>(
        claims: Claims,
        issuer_data: (&DIDURL, S),
        holder_data: (&DIDURL, K),
        metadata: VCMetadata,
        did_resolver: UniversalResolver,
    ) -> Result<VC>
    where
        S: Signer + Key,
        K: Key,
    {
        trace!(issuer_did_url = ?{issuer_data.0}, holder_did_url = ?{holder_data.0});

        let iss_did = issuer_data.0.did();
        let holder_did = holder_data.0.did();

        let vc = JsonLdAPI::create_credential(
            &metadata,
            iss_did.as_str(),
            Some(holder_did.as_str()),
            claims,
        )?;

        JsonLdAPI::sign_credential(vc, issuer_data, metadata.mandatory_claims, did_resolver).await
    }

    #[instrument(level = Level::TRACE, skip(holder_signer, did_resolver), err(), ret())]
    async fn create_vp<S>(
        credential: &VC,
        holder_signer: S,
        metadata: VPMetadata,
        did_resolver: UniversalResolver,
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

        let holder_did = credential
            .parse_claims()?
            .get("credentialSubject")
            .ok_or_else(|| {
                PresentationSnafu {
                    details: "Could not parse 'credentialSubject' field of vc",
                }
                .build()
            })?
            .get("id")
            .and_then(|c| c.as_str())
            .ok_or_else(|| {
                PresentationSnafu {
                    details: "Could not parse subject 'id' of vc",
                }
                .build()
            })?
            .to_owned();

        if Self::is_bbs_plus_signed(credential) {
            //TODO how to enable/disable holder binding for bbs plus signed ldp vc presentation?
            return Self::create_vp_for_bbs_plus_signed_vc(
                credential.to_owned(),
                metadata,
                &holder_did,
                did_resolver,
            )
            .await;
        }
        let vp = JsonLdAPI::create_presentation(credential.to_owned(), &metadata, &holder_did)?;

        let verifier = VerificationParameters::from_resolver(&did_resolver);

        let (suite, sign_opts) = match &credential.claims {
            Credential::V2(_) => {
                Self::select_crypto_suite_for_v2_signing(&holder_signer.alg(), None)?
            }
            _ => {
                let suite = AnySuite::pick(&key, None).ok_or_else(|| {
                    CryptoSuiteCreationSnafu {
                        details: "Could not pick crypto suite to sign json-ld v1 credential",
                    }
                    .build()
                })?;

                (suite, Default::default())
            }
        };

        let signer = LocalSigner(JsonLdSigner {
            signer: Arc::new(holder_signer),
        });

        let verification_method = did_resolver
            .resolve_into_any_verification_method(ssi::dids::DID::new(&holder_did).map_err(
                |e| {
                    DIDSnafu {
                        details: e.to_string(),
                    }
                    .build()
                },
            )?)
            .await
            .map_err(|e| {
                CredentialCreationSnafu {
                    details: format!("Can not resolve verification method: {e}"),
                }
                .build()
            })?
            .ok_or_else(|| {
                CredentialCreationSnafu {
                    details: "Can not find verification method",
                }
                .build()
            })?;
        let verification_method_id =
            IriBuf::from_str(&verification_method.id).context(IriBufParsingSnafu)?;

        let mut params = ProofOptions::from_method_and_options(
            ReferenceOrOwned::Reference(verification_method_id.clone()),
            AnyInputSuiteOptions::new(),
        );
        let (nonce, aud) = if let Some(hb) = metadata.holder_binder {
            (Some(hb.nonce.secret().to_string()), Some(hb.verifier_id))
        } else {
            (None, None)
        };
        params.nonce = nonce.to_owned();
        params.challenge = nonce;
        params.domains = aud.map(|a| vec![a]).unwrap_or(vec![]);

        suite
            .sign(vp, did_resolver.clone(), &signer, params)
            .await
            .context(SpruceSigningSnafu)
    }

    #[instrument(level = Level::TRACE, skip(did_resolver), err(), ret())]
    async fn verify_vc(
        credential: &VC,
        opts: VerifyOptions,
        did_resolver: UniversalResolver,
    ) -> Result<()> {
        let verifier = VerificationParameters::from_resolver(did_resolver);

        let credential = if Self::is_bbs_plus_signed(credential) {
            let selection_opts = Self::prepare_bbs_plus_selection_opts(opts)?;

            &Self::create_derived_vc_from_base(credential, &verifier, selection_opts).await?
        } else {
            credential
        };

        let _ = credential
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

    #[instrument(level = Level::TRACE, skip(holder_binder, did_resolver), err(), ret())]
    async fn verify_vp(
        presentation: &VP,
        //TODO. Add verification with holder binder
        holder_binder: Option<HolderBinder>,
        opts: VerifyOptions,
        did_resolver: UniversalResolver,
    ) -> Result<()> {
        let verifier = VerificationParameters::from_resolver(did_resolver);

        match &presentation.claims {
            Presentation::V2(vp) if presentation.proofs.is_empty() => {
                for vc in &vp.verifiable_credentials {
                    let is_bbs_signed = vc.proofs.iter().any(|s| s.type_ == AnySuite::Bbs2023);

                    ensure!(
                        is_bbs_signed,
                        VerifyingSnafu {
                            details: "Verifiable Presentation does not contain a proof"
                        }
                    );

                    vc.verify(&verifier)
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
                }
            }
            _ => {
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
            }
        }

        Ok(())
    }
}

impl<S: Signer + Key> MessageSigner<ssi::crypto::Algorithm> for JsonLdSigner<S> {
    async fn sign(
        self,
        algorithm: ssi::crypto::AlgorithmInstance,
        message: &[u8],
    ) -> std::result::Result<Vec<u8>, MessageSignatureError> {
        match &algorithm {
            ssi::crypto::AlgorithmInstance::EdDSA | ssi::crypto::AlgorithmInstance::ES256 => self
                .signer
                .sign(message)
                .await
                .map_err(|e| MessageSignatureError::SignatureFailed(e.to_string())),

            ssi::crypto::AlgorithmInstance::Bbs(instance) => {
                self.sign_multi(algorithm, &[message.to_vec()]).await
            }
            _ => Err(MessageSignatureError::UnsupportedAlgorithm(format!(
                "{}",
                algorithm.algorithm()
            ))),
        }
    }

    async fn sign_multi(
        self,
        algorithm: ssi::crypto::AlgorithmInstance,
        messages: &[Vec<u8>],
    ) -> std::result::Result<Vec<u8>, MessageSignatureError> {
        match algorithm {
            ssi::crypto::AlgorithmInstance::Bbs(instance) => {
                let signing_opts = SigningOptions::BBS(*instance.0);
                self.signer
                    .sign_multi(messages, Some(signing_opts))
                    .await
                    .map_err(|e| MessageSignatureError::SignatureFailed(e.to_string()))
            }
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
    use crate::did::DIDURLBuf;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::nonce::LocalNonceHandler;
    use crate::kms::KeyType;
    use crate::nonce::NonceHandler;
    use crate::utils::test_utils::create_did_url_and_key_handle;
    use crate::utils::test_utils::{failed_signer_key, no_jwk_key};
    use crate::vc::claims::Claim;
    use crate::vc::formats::Error;
    use crate::vc::oid4vci::IssuerUrl;
    use rstest::rstest;
    use serde_json::{Value, json};

    #[rstest]
    #[case::p256(KeyType::P256, "EcdsaSecp256r1Signature2019")]
    #[case::ed25519(KeyType::Ed25519, "Ed25519Signature2018")]
    #[tokio::test]
    async fn vc_v1_issuance_and_verification_works_correctly(
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
            Some(Duration::days(5 * 365)),
        )
        .unwrap();

        let vc = JsonLdAPI::create_vc(
            sample_claims(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh),
            metadata,
            UniversalResolver::default(),
        )
        .await
        .unwrap();

        JsonLdAPI::verify_vc(&vc, VerifyOptions::default(), UniversalResolver::default())
            .await
            .unwrap();

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

    #[rstest]
    #[case::p256(KeyType::P256, "ecdsa-rdfc-2019")]
    #[case::ed25519(KeyType::Ed25519, "eddsa-rdfc-2022")]
    #[tokio::test]
    async fn vc_v2_issuance_and_verification_works_correctly(
        #[case] iss_key_type: KeyType,
        #[case] proof_type: &str,
    ) {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, iss_key_type).await;

        let metadata = VCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/ns/credentials/v2").unwrap(),
                IriRefBuf::from_str("https://www.w3.org/ns/credentials/examples/v2").unwrap(),
            ],
            vec![
                "VerifiableCredential".to_string(),
                "AlumniCredential".to_string(),
            ],
            Some(Duration::days(5 * 365)),
        )
        .unwrap();

        let claims = json!({
            "id": hld_did_url.did().to_string(),
            "alumniOf": "The School of Examples"
        });
        let vc = JsonLdAPI::create_vc(
            claims.clone().try_into().unwrap(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh),
            metadata,
            UniversalResolver::default(),
        )
        .await
        .unwrap();

        JsonLdAPI::verify_vc(&vc, VerifyOptions::default(), UniversalResolver::default())
            .await
            .unwrap();

        let vc = serde_json::to_value(vc)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        let proof = vc.get("proof").unwrap().as_object().unwrap().clone();

        assert_eq!(
            vc.get("@context").unwrap(),
            &json!([
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ])
        );
        assert_eq!(
            vc.get("type").unwrap(),
            &json!(["VerifiableCredential", "AlumniCredential"])
        );
        assert_eq!(vc.get("credentialSubject").unwrap(), &claims);
        assert_eq!(
            vc.get("issuer").unwrap(),
            &json!(iss_did_url.did().to_string())
        );
        assert!(vc.contains_key("validFrom"));
        assert!(vc.contains_key("validUntil"));
        assert_eq!(
            proof.get("type").unwrap(),
            &json!("DataIntegrityProof".to_string())
        );
        assert_eq!(
            proof.get("proofPurpose").unwrap(),
            &json!("assertionMethod")
        );
        assert_eq!(proof.get("cryptosuite").unwrap(), &json!(proof_type));
        assert!(proof.contains_key("verificationMethod"));
        assert!(proof.contains_key("created"));
        assert!(proof.contains_key("proofValue"));
    }

    #[tokio::test]
    async fn bbs_signed_vc_issuance_and_verification_works_correctly() {
        let kms = LocalKms::new();
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::Bls12381).await;
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let mut metadata = VCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/ns/credentials/v2").unwrap(),
                IriRefBuf::from_str("https://www.w3.org/ns/credentials/examples/v2").unwrap(),
            ],
            vec![
                "VerifiableCredential".to_string(),
                "AlumniCredential".to_string(),
            ],
            Some(time::Duration::days(5 * 365)),
        )
        .unwrap();

        let claims = json!({
            "id": hld_did_url.did().to_string(),
            "alumniOf": "The School of Examples"
        });

        metadata.mandatory_claims = Some(vec!["/type".parse().unwrap()]);
        metadata.credential_id =
            Some(UriBuf::from_str("urn:uuid:7a6cafb9-11c3-41a8-98d8-8b5a45c2548f").unwrap());

        let vc_base = JsonLdAPI::create_vc(
            claims.clone().try_into().unwrap(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh.clone()),
            metadata,
            UniversalResolver::default(),
        )
        .await
        .unwrap();
        let ver_opts = VerifyOptions {
            selective_claims: Some(vec![
                "/type".parse().unwrap(),
                "/issuer".parse().unwrap(),
                "/credentialSubject/id".parse().unwrap(),
                "/credentialSubject/alumniOf".parse().unwrap(),
            ]),
        };
        JsonLdAPI::verify_vc(&vc_base, ver_opts, UniversalResolver::default())
            .await
            .unwrap();

        let vc = serde_json::to_value(&vc_base)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        let proof = vc.get("proof").unwrap().as_object().unwrap().clone();

        let mut expected_cred_subject: Claims = claims.try_into().unwrap();
        expected_cred_subject.insert(
            "id".to_string(),
            Claim::String(hld_did_url.did().to_string()),
        );

        let expected_cred_subject: Value = expected_cred_subject.try_into().unwrap();
        assert_eq!(
            vc.get("@context").unwrap(),
            &json!([
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ])
        );
        assert_eq!(
            vc.get("type").unwrap(),
            &json!(["VerifiableCredential", "AlumniCredential"])
        );
        assert_eq!(vc.get("credentialSubject").unwrap(), &expected_cred_subject);
        assert_eq!(
            vc.get("issuer").unwrap(),
            &json!(iss_did_url.did().to_string())
        );
        assert!(vc.contains_key("validFrom"));
        assert!(vc.contains_key("validUntil"));
        assert_eq!(
            proof.get("type").unwrap(),
            &json!("DataIntegrityProof".to_string())
        );
        assert_eq!(
            proof.get("proofPurpose").unwrap(),
            &json!("assertionMethod")
        );
        assert_eq!(
            proof.get("cryptosuite").unwrap(),
            &json!("bbs-2023".to_string())
        );
        assert!(proof.contains_key("verificationMethod"));
        assert!(proof.contains_key("created"));
        assert!(proof.contains_key("proofValue"));
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
            Some(Duration::days(5 * 365)),
        )
        .unwrap();

        let result = JsonLdAPI::create_vc(
            sample_claims(),
            (&iss_did_url, failed_signer_key(iss_kh)),
            (&hld_did_url, hld_kh),
            metadata,
            UniversalResolver::default(),
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
            Some(Duration::days(5 * 365)),
        )
        .unwrap();

        let result = JsonLdAPI::create_vc(
            sample_claims(),
            (&iss_did_url, no_jwk_key()),
            (&hld_did_url, hld_kh),
            metadata,
            UniversalResolver::default(),
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
            Some(Duration::days(5 * 365)),
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
            UniversalResolver::default(),
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
    async fn vp_v1_generation_and_verification_work_correctly(
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
            Some(Duration::days(5 * 365)),
        )
        .unwrap();

        let vc = JsonLdAPI::create_vc(
            sample_claims(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh.clone()),
            metadata,
            UniversalResolver::default(),
        )
        .await
        .unwrap();

        let nonce = LocalNonceHandler::default().generate().await.unwrap();

        let presentation = JsonLdAPI::create_vp(
            &vc,
            hld_kh,
            VPMetadata::new(
                &vc,
                Some(HolderBinder {
                    nonce: nonce.to_owned(),
                    verifier_id: "verifier_id".to_string(),
                }),
            )
            .unwrap(),
            UniversalResolver::default(),
        )
        .await
        .unwrap();

        JsonLdAPI::verify_vp(
            &presentation,
            Some(HolderBinder {
                nonce,
                verifier_id: "verifier_id".to_string(),
            }),
            VerifyOptions::default(),
            UniversalResolver::default(),
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

    #[rstest]
    #[case::p256(KeyType::P256, "ecdsa-rdfc-2019")]
    #[case::ed25519(KeyType::Ed25519, "eddsa-rdfc-2022")]
    #[tokio::test]
    async fn vp_v2_generation_and_verification_works_correctly(
        #[case] holder_key_type: KeyType,
        #[case] proof_type: &str,
    ) {
        let kms = LocalKms::new();
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, holder_key_type).await;
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let metadata = VCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/ns/credentials/v2").unwrap(),
                IriRefBuf::from_str("https://www.w3.org/ns/credentials/examples/v2").unwrap(),
            ],
            vec![
                "VerifiableCredential".to_string(),
                "AlumniCredential".to_string(),
            ],
            Some(Duration::days(5 * 365)),
        )
        .unwrap();

        let claims = json!({
            "id": hld_did_url.did().to_string(),
            "alumniOf": "The School of Examples"
        });
        let vc = JsonLdAPI::create_vc(
            claims.clone().try_into().unwrap(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh.clone()),
            metadata,
            UniversalResolver::default(),
        )
        .await
        .unwrap();

        let nonce = LocalNonceHandler::default().generate().await.unwrap();

        let presentation = JsonLdAPI::create_vp(
            &vc,
            hld_kh,
            VPMetadata::new(
                &vc,
                Some(HolderBinder {
                    nonce: nonce.to_owned(),
                    verifier_id: "verifier_id".to_string(),
                }),
            )
            .unwrap(),
            UniversalResolver::default(),
        )
        .await
        .unwrap();

        JsonLdAPI::verify_vp(
            &presentation,
            Some(HolderBinder {
                nonce,
                verifier_id: "verifier_id".to_string(),
            }),
            VerifyOptions::default(),
            UniversalResolver::default(),
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
            &json!(["https://www.w3.org/ns/credentials/v2",])
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
        assert_eq!(
            proof.get("type").unwrap(),
            &json!("DataIntegrityProof".to_string())
        );
        assert_eq!(
            proof.get("proofPurpose").unwrap(),
            &json!("assertionMethod")
        );
        assert_eq!(proof.get("cryptosuite").unwrap(), &json!(proof_type));
        assert!(proof.contains_key("verificationMethod"));
        assert!(proof.contains_key("created"));
        assert!(proof.contains_key("proofValue"));
    }

    #[tokio::test]
    async fn bbs_signed_vp_verification_works_correctly() {
        let kms = LocalKms::new();
        let (iss_did_url, iss_kh) = create_did_url_and_key_handle(&kms, KeyType::Bls12381).await;
        let (hld_did_url, hld_kh) = create_did_url_and_key_handle(&kms, KeyType::P256).await;

        let mut metadata = VCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/ns/credentials/v2").unwrap(),
                IriRefBuf::from_str("https://www.w3.org/ns/credentials/examples/v2").unwrap(),
            ],
            vec![
                "VerifiableCredential".to_string(),
                "AlumniCredential".to_string(),
            ],
            Some(Duration::days(5 * 365)),
        )
        .unwrap();

        let claims = json!({
            "id": hld_did_url.did().to_string(),
            "alumniOf": "The School of Examples",
            "degree": "Bachelor of Schools",
        });

        metadata.mandatory_claims = Some(vec!["/type".parse().unwrap()]);
        metadata.credential_id =
            Some(UriBuf::from_str("urn:uuid:7a6cafb9-11c3-41a8-98d8-8b5a45c2548f").unwrap());

        let vc_base = JsonLdAPI::create_vc(
            claims.clone().try_into().unwrap(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh.clone()),
            metadata,
            UniversalResolver::default(),
        )
        .await
        .unwrap();

        let nonce = LocalNonceHandler::default().generate().await.unwrap();
        let mut vp_metadata = VPMetadata::new(
            &vc_base,
            Some(HolderBinder {
                nonce: nonce.to_owned(),
                verifier_id: "verifier_id".to_string(),
            }),
        )
        .unwrap();
        vp_metadata.disclosures = vec![
            "/type".parse().unwrap(),
            "/issuer".parse().unwrap(),
            "/credentialSubject/alumniOf".parse().unwrap(),
        ];
        let vp = JsonLdAPI::create_vp(&vc_base, hld_kh, vp_metadata, UniversalResolver::default())
            .await
            .unwrap();

        JsonLdAPI::verify_vp(
            &vp,
            Some(HolderBinder {
                nonce,
                verifier_id: "verifier_id".to_string(),
            }),
            VerifyOptions::default(),
            UniversalResolver::default(),
        )
        .await
        .unwrap();
        let vp = serde_json::to_value(vp)
            .unwrap()
            .as_object()
            .unwrap()
            .clone();

        assert_eq!(
            vp.get("@context").unwrap(),
            &json!(["https://www.w3.org/ns/credentials/v2"])
        );
        assert_eq!(vp.get("type").unwrap(), &json!(["VerifiablePresentation"]));
        assert!(!vp.contains_key("proof"));

        let vc = vp
            .get("verifiableCredential")
            .unwrap()
            .as_object()
            .unwrap()
            .clone();
        assert_eq!(
            vc.get("credentialSubject").unwrap(),
            &serde_json::to_value(json!({
                "id": hld_did_url.did().to_string(),
                "alumniOf": "The School of Examples"
            }))
            .unwrap()
        );

        let vc_proof = vc.get("proof").unwrap().as_object().unwrap().clone();
        assert_eq!(
            vc_proof.get("type").unwrap(),
            &json!("DataIntegrityProof".to_string())
        );
        assert_eq!(
            vc_proof.get("proofPurpose").unwrap(),
            &json!("assertionMethod")
        );
        assert_eq!(
            vc_proof.get("cryptosuite").unwrap(),
            &json!("bbs-2023".to_string())
        );
        assert!(vc_proof.contains_key("verificationMethod"));
        assert!(vc_proof.contains_key("created"));
        assert!(vc_proof.contains_key("proofValue"));
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
            Some(Duration::days(5 * 365)),
        )
        .unwrap();

        let vc = JsonLdAPI::create_vc(
            sample_claims(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh.clone()),
            metadata,
            UniversalResolver::default(),
        )
        .await
        .unwrap();

        let nonce = LocalNonceHandler::default().generate().await.unwrap();

        let result = JsonLdAPI::create_vp(
            &vc,
            failed_signer_key(hld_kh),
            VPMetadata::new(
                &vc,
                Some(HolderBinder {
                    nonce,
                    verifier_id: "verifier_id".to_string(),
                }),
            )
            .unwrap(),
            UniversalResolver::default(),
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
            Some(Duration::days(5 * 365)),
        )
        .unwrap();

        let vc = JsonLdAPI::create_vc(
            sample_claims(),
            (&iss_did_url, iss_kh),
            (&hld_did_url, hld_kh),
            metadata,
            UniversalResolver::default(),
        )
        .await
        .unwrap();

        let nonce = LocalNonceHandler::default().generate().await.unwrap();

        let result = JsonLdAPI::create_vp(
            &vc,
            no_jwk_key(),
            VPMetadata::new(
                &vc,
                Some(HolderBinder {
                    nonce,
                    verifier_id: "verifier_id".to_string(),
                }),
            )
            .unwrap(),
            UniversalResolver::default(),
        )
        .await;

        assert!(matches!(
            result.err().unwrap(),
            Error::KeyTypeNotSupported { .. }
        ));
    }

    fn sample_claims() -> Claims {
        json!({
            "type": ["PermanentResident", "Person"],
            "givenName": "JANE",
            "familyName": "SMITH",
            "gender": "Female",
            "image": "data:image/png;base64,iVBORw0KGgoAA...Jggg==",
            "id": "urn:uuid:7a6cafb9-11c3-41a8-98d8-8b5a45c2548f",
            "residentSince": "2015-01-01",
            // "lprCategory": "C09",
            // "lprNumber": "999-999-999",
            "commuterClassification": "C1",
            "birthCountry": "Arcadia",
            "birthDate": "1978-07-17"
        })
        .try_into()
        .unwrap()
    }

    #[rstest]
    #[case::url(
        example_credential("https://university.example/issuers/14"),
        CredentialIssuerIdentifier::OID4VCI(IssuerUrl::new("https://university.example/issuers/14".to_string()).unwrap()),
    )]
    #[case::url_in_obj(
        example_credential_issuer_obj("https://university.example/issuers/14"),
        CredentialIssuerIdentifier::OID4VCI(IssuerUrl::new("https://university.example/issuers/14".to_string()).unwrap()),
    )]
    #[case::did(
        example_credential("did:example:123"),
        CredentialIssuerIdentifier::DID(DIDURLBuf::from_str("did:example:123").unwrap()),
    )]
    #[case::did_in_obj(
        example_credential_issuer_obj("did:example:123"),
        CredentialIssuerIdentifier::DID(DIDURLBuf::from_str("did:example:123").unwrap()),
    )]
    #[case::other(
        example_credential("notadid:example:123"),
        CredentialIssuerIdentifier::Other("notadid:example:123".to_string()),
    )]
    #[case::other_in_obj(
        example_credential_issuer_obj("notadid:example:123"),
        CredentialIssuerIdentifier::Other("notadid:example:123".to_string()),
    )]
    fn extract_issuer_identifier(
        #[case] credential: VC,
        #[case] expected: CredentialIssuerIdentifier,
    ) {
        let actual = JsonLdAPI::extract_issuer_identifier(&credential).unwrap();
        assert_eq!(actual, Some(expected));
    }

    fn example_credential(issuer: &str) -> VC {
        let cred_str = r#"{
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": "ISSUER",
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                    "type": "ExampleBachelorDegree",
                    "name": "Bachelor of Science and Arts"
                }
            }
        }"#
        .replace("ISSUER", issuer);
        serde_json::from_str(cred_str.as_str()).unwrap()
    }

    fn example_credential_issuer_obj(issuer: &str) -> VC {
        let cred_str = r#"{
            "@context": [
                "https://www.w3.org/ns/credentials/v2",
                "https://www.w3.org/ns/credentials/examples/v2"
            ],
            "id": "http://university.example/credentials/3732",
            "type": ["VerifiableCredential", "ExampleDegreeCredential"],
            "issuer": {
                "id": "ISSUER"
            },
            "validFrom": "2010-01-01T19:23:24Z",
            "credentialSubject": {
                "id": "did:example:ebfeb1f712ebc6f1c276e12ec21",
                "degree": {
                    "type": "ExampleBachelorDegree",
                    "name": "Bachelor of Science and Arts"
                }
            }
        }"#
        .replace("ISSUER", issuer);
        serde_json::from_str(cred_str.as_str()).unwrap()
    }
}
