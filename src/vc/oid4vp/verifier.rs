use async_trait::async_trait;
use openid4vp::core::authorization_request::parameters::{
    HashAlgorithm, IdTokenType, Nonce as NonceSpruce, Scope, State, TransactionData,
};
use openid4vp::core::metadata::WalletMetadata;
use openid4vp::verifier::by_reference::ByReference;
use openid4vp::verifier::request_builder::RequestType;
use serde_json::{Value as Json, Value};
use snafu::{ResultExt, ensure};
use std::fmt::Debug;
use std::marker::PhantomData;
use tracing::{Level, debug, info, instrument, trace};
use url::Url;

use crate::crypto::JWK;
use crate::did::JWKResolver;
use crate::did::universal::UniversalResolver;
use crate::http::HttpClient;
use crate::jwe::JweDecrypt;
use crate::kms::{KeyHandle, Kms};
use crate::nonce::{Nonce, NonceHandler};
use crate::utils::wasm::{WasmNotSend, WasmNotSync};
use crate::vc;
use crate::vc::claims::{Claim, Claims};
use crate::vc::core::{HolderBinder, KeyMetadata};
use crate::vc::dcql::validate_credentials;
use crate::vc::oid4vp::Error::{Internal, Protocol};
use crate::vc::oid4vp::internal_error::{
    AuthorizationResponseDecryptionSnafu, ClaimsSnafu, ClientSnafu, DCQLSnafu,
    DidUrlResolutionSnafu, IdTokenValidationSnafu, JsonSnafu, KMSSnafu, NonceGenerationSnafu,
    Oid4VpLibSnafu, ParseSnafu, PresentationExchangeSnafu, VCSnafu,
};
use crate::vc::oid4vp::metadata::{default_client_metadata, default_wallet_metadata};
use crate::vc::oid4vp::protocol_error::ErrorType;
use crate::vc::oid4vp::signer::Signer;
use crate::vc::oid4vp::{
    AuthorizationRequestMetadata, AuthorizationResponse, AuthorizationResponseObject, ClientId,
    ClientMetadata, CredentialVerificationMetadata, PRESENTATION_SUBMISSION, PassAuthRequestObject,
    PresentationSession, ProtocolError, ResolvedPresentationQuery, ResponseMode, ResponseType,
    STATE, TRANSACTION_DATA_HASHES, TRANSACTION_DATA_HASHES_ALG, TransactionDataItem,
    TransactionDataResponse, get_transaction_data_hash,
};
use crate::vc::presentation_exchange;
use crate::vc::presentation_exchange::{
    PresentationResponse, validate_against_presentation_definition,
};
use crate::vc::{dcql, oid4vp as api};
use one_core_asdk::one_crypto::jwe::extract_jwe_header;
use openid4vp::core::authorization_request::RequestReference;
use openid4vp::core::response::parameters::{IdTokenBody as IdToken, TransactionDataHashesAlg};
use ssi::dids::DIDURLBuf;
use std::collections::HashMap;
use std::ops::Deref;

pub type Error = api::Error;
pub type Result<T> = core::result::Result<T, Error>;

pub type DecentralizedIdentifierClient<S> =
    openid4vp::verifier::client::DecentralizedIdentifierClient<S>;
pub type X509Client = openid4vp::verifier::client::X509Client;
pub type RedirectUriClient = openid4vp::verifier::client::RedirectUriClient;
const VP_TOKEN: &str = "vp_token";
const ID_TOKEN: &str = "id_token";

#[derive(Debug, Clone)]
pub struct VerifierMetadata {
    pub client_id: ClientId,
    pub key_metadata: KeyMetadata,
    pub client_metadata: ClientMetadata,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct PresentationVerificationOptions {
    pub enc_pub_key: Option<JWK>,
    pub audience: Option<String>,
}

pub struct VerifierService<VF, KH, KMS, NG, HC>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH> + JweDecrypt<KH>,
    NG: NonceHandler,
    HC: HttpClient,
{
    verifier: VF,
    metadata: VerifierMetadata,
    kms: KMS,
    nonce_generator: NG,
    http_client: HC,
    public_jwk_resolver: UniversalResolver,
    _marker: PhantomData<KH>,
}

impl<VF, KH, KMS, NG, HC> VerifierService<VF, KH, KMS, NG, HC>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH> + JweDecrypt<KH>,
    NG: NonceHandler,
    HC: HttpClient,
{
    #[allow(clippy::too_many_arguments)]
    #[instrument(
        level = Level::TRACE,
        skip(verifier, kms, nonce_generator, http_client, did_resolver)
    )]
    pub fn new(
        verifier: VF,
        kms: KMS,
        nonce_generator: NG,
        http_client: HC,
        client_id: ClientId,
        key_metadata: KeyMetadata,
        did_resolver: UniversalResolver,
        client_metadata: Option<ClientMetadata>,
    ) -> Self {
        let metadata = VerifierMetadata {
            client_id,
            key_metadata,
            client_metadata: client_metadata.unwrap_or(default_client_metadata()),
        };

        info!("oid4vp-verifier service is initialized");

        Self {
            metadata,
            public_jwk_resolver: did_resolver,
            kms,
            nonce_generator,
            http_client,
            verifier,
            _marker: Default::default(),
        }
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<VF, KH, KMS, NG, HC> api::Verifier for VerifierService<VF, KH, KMS, NG, HC>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH> + JweDecrypt<KH>,
    NG: NonceHandler,
    HC: HttpClient,
{
    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn create_authorization_request(
        &self,
        resolved_presentation_query: &ResolvedPresentationQuery,
        auth_request_metadata: &AuthorizationRequestMetadata,
        wallet_metadata: Option<&WalletMetadata>,
    ) -> Result<(Url, PresentationSession)> {
        info!("creating authorization request object is started");
        let nonce = self
            .nonce_generator
            .generate()
            .await
            .context(NonceGenerationSnafu)?;

        let (request_url, auth_request_jwt) = self
            .build_authorization_request(
                resolved_presentation_query,
                nonce.clone(),
                wallet_metadata.unwrap_or(&default_wallet_metadata()),
                auth_request_metadata,
            )
            .await?;

        let session = PresentationSession {
            nonce,
            auth_request_jwt,
            resolved_presentation_query: resolved_presentation_query.to_owned(),
        };

        info!("authorization request object is created");

        Ok((request_url, session))
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn verify_presentation(
        &self,
        authorization_response: &AuthorizationResponse,
        session: &PresentationSession,
        verification_metadata: &CredentialVerificationMetadata,
    ) -> Result<Claims> {
        Ok(self
            .verify_and_extract_presentation(authorization_response, session, verification_metadata)
            .await?
            .0)
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn verify_and_extract_presentation(
        &self,
        authorization_response: &AuthorizationResponse,
        session: &PresentationSession,
        verification_metadata: &CredentialVerificationMetadata,
    ) -> Result<(Claims, HashMap<String, Vec<crate::vc::Presentation>>)> {
        let (authorization_response, mut verification_opts) = self
            .resolve_authorization_response(authorization_response)
            .await?;
        self.validate_transaction_data(
            verification_metadata.transaction_data.as_ref(),
            authorization_response.transaction_data_response.as_ref(),
        )?;

        verification_opts.audience = verification_metadata.audience.clone();
        let (vp_token_claims, presentations) = self
            .do_verify_presentation(
                &session.resolved_presentation_query,
                &session.nonce,
                &authorization_response,
                verification_opts,
            )
            .await?;

        let mut claims = Claims::new();
        claims.insert(VP_TOKEN.to_string(), vp_token_claims);

        if let Some(id_token) = &authorization_response.id_token {
            let id_token_claims = self.validate_id_token(id_token, &session.nonce).await?;

            // TODO: get rid of IdTokenBody -> Value conversion, implement IdTokenBody -> Claim instead
            let id_token_claims = serde_json::to_value(id_token_claims).context(JsonSnafu)?;
            claims.insert(ID_TOKEN.to_string(), id_token_claims.into());

            info!("ID token is verified");
        }

        info!("presentation is verified");

        Ok((claims, presentations))
    }
}

impl<VF, KH, KMS, NG, HC> VerifierService<VF, KH, KMS, NG, HC>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH> + JweDecrypt<KH>,
    NG: NonceHandler,
    HC: HttpClient,
{
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn resolve_authorization_response(
        &self,
        response: &AuthorizationResponse,
    ) -> Result<(AuthorizationResponseObject, PresentationVerificationOptions)> {
        match response {
            AuthorizationResponse::Plain(auth_response) => {
                Ok((auth_response.to_owned(), Default::default()))
            }
            AuthorizationResponse::Jwe(jwe_response) => {
                let header = extract_jwe_header(jwe_response).map_err(|e| Internal {
                    source: AuthorizationResponseDecryptionSnafu {
                        details: format!("Error while getting the jwe header: {}", e),
                    }
                    .build(),
                })?;
                let kh = self.kms.get(&header.key_id).await.map_err(|e| Internal {
                    source: AuthorizationResponseDecryptionSnafu {
                        details: format!(
                            "Error while getting the key handle for {} : {}",
                            header.key_id, e
                        ),
                    }
                    .build(),
                })?;
                let enc_pub_key = kh.jwk();
                trace!(
                    "JWE Authorization Response encryption public info: {:?}",
                    enc_pub_key
                );
                let claim_set = self
                    .kms
                    .decrypt(jwe_response, &header.key_id)
                    .await
                    .map_err(|e| Internal {
                        source: AuthorizationResponseDecryptionSnafu {
                            details: format!(
                                "Failed to decrypt Encrypted Authorization Response: {}",
                                e
                            ),
                        }
                        .build(),
                    })?;
                let Value::Object(claim_set) = claim_set else {
                    return Err(Internal {
                        source: AuthorizationResponseDecryptionSnafu {
                            details: "Error: The claim set must be an object",
                        }
                        .build(),
                    });
                };
                debug!("Decrypted JWE Authorization Response");
                let vp_token = claim_set
                    .get(VP_TOKEN)
                    .ok_or(Internal {
                        source: AuthorizationResponseDecryptionSnafu {
                            details: "Error: vp_token was not found".to_string(),
                        }
                        .build(),
                    })?
                    .to_owned();
                let presentation_submission = claim_set
                    .get(PRESENTATION_SUBMISSION)
                    .and_then(|value: &Value| serde_json::from_value(value.to_owned()).ok());
                let id_token = claim_set
                    .get(ID_TOKEN)
                    .and_then(|value: &Value| serde_json::from_value(value.to_owned()).ok());
                let state = claim_set
                    .get(STATE)
                    .and_then(|value: &Value| serde_json::from_value(value.to_owned()).ok());
                let transaction_data_hashes = claim_set
                    .get(TRANSACTION_DATA_HASHES)
                    .and_then(|value: &Value| serde_json::from_value(value.to_owned()).ok());
                let transaction_data_hashes_alg = claim_set
                    .get(TRANSACTION_DATA_HASHES_ALG)
                    .and_then(|value: &Value| serde_json::from_value(value.to_owned()).ok());
                let transaction_data_response =
                    transaction_data_hashes.map(|tdh| TransactionDataResponse {
                        transaction_data_hashes: tdh,
                        transaction_data_hashes_alg,
                    });
                debug!("Converted decrypted JWE body to Authorization Response properties");
                Ok((
                    AuthorizationResponseObject {
                        vp_token,
                        presentation_submission,
                        id_token,
                        state,
                        transaction_data_response,
                    },
                    PresentationVerificationOptions {
                        enc_pub_key,
                        audience: None,
                    },
                ))
            }
        }
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn validate_id_token(&self, id_token: &str, nonce: &Nonce) -> Result<IdToken> {
        let header: ssi::claims::jws::Header = ssi::claims::jws::decode_unverified(id_token)
            .map_err(|e| {
                IdTokenValidationSnafu {
                    details: format!("could not parse id token: {e}"),
                }
                .build()
            })?
            .0;

        ensure!(
            header.type_ == Some("JWT".to_string()),
            IdTokenValidationSnafu {
                details: "header 'typ' must be 'JWT'",
            }
        );

        ensure!(
            header.algorithm != ssi::jwk::Algorithm::None,
            IdTokenValidationSnafu {
                details: "header must contain 'alg' claim",
            }
        );

        let (did, jwk) = self
            .resolve_did_and_jwk_from_id_token_header(header)
            .await?;
        let id_token: IdToken = ssi::claims::jwt::decode_verify(id_token, &jwk).map_err(|e| {
            IdTokenValidationSnafu {
                details: format!("could not decode and validate id token: {e}"),
            }
            .build()
        })?;

        ensure!(
            id_token.audience == self.metadata.client_id.to_string(),
            IdTokenValidationSnafu {
                details: &format!(
                    "id token audience value mismatch, expected {}, got {}",
                    self.metadata.client_id, id_token.audience
                ),
            }
        );

        ensure!(
            id_token.nonce == nonce.secret(),
            IdTokenValidationSnafu {
                details: "incorrect nonce".to_string(),
            }
        );

        ensure!(
            id_token.subject == did && id_token.issuer == did,
            IdTokenValidationSnafu {
                details: &format!(
                    "id token 'subject' and 'issuer' values must be equal, expected {}, got 'subject' = {} and 'issuer' = {}",
                    did, id_token.subject, id_token.issuer
                ),
            }
        );

        ensure!(
            id_token.expiration_time > time::OffsetDateTime::now_utc().unix_timestamp(),
            IdTokenValidationSnafu {
                details: "id token is expired".to_string(),
            }
        );

        Ok(id_token)
    }

    fn validate_transaction_data(
        &self,
        expected_td: Option<&Vec<TransactionDataItem>>,
        td_hashes: Option<&TransactionDataResponse>,
    ) -> Result<()> {
        match (expected_td, td_hashes) {
            (Some(_), None) => {
                return Err(Protocol {
                    source: ProtocolError::new(
                        ErrorType::InvalidTransactionData,
                        Some(
                            "Transaction data hashes were not provided but were expected"
                                .to_string(),
                        ),
                        None,
                    ),
                });
            }
            (Some(td), Some(td_response)) => {
                if td.len() != td_response.transaction_data_hashes.0.len() {
                    let err_msg = format!(
                        "Wrong length of hashes provided for transaction data. Expected: {}, Provided: {}",
                        td.len(),
                        td_response.transaction_data_hashes.0.len()
                    );
                    return Err(Protocol {
                        source: ProtocolError::new(
                            ErrorType::InvalidTransactionData,
                            Some(err_msg),
                            None,
                        ),
                    });
                } else {
                    for (expected, actual) in
                        td.iter().zip(td_response.transaction_data_hashes.0.iter())
                    {
                        let hash_alg = td_response
                            .transaction_data_hashes_alg
                            .to_owned()
                            .unwrap_or(TransactionDataHashesAlg(HashAlgorithm::Sha256))
                            .0;
                        let encoded_expected_hash = get_transaction_data_hash(expected, hash_alg)?;
                        if encoded_expected_hash.as_str() != actual.as_str() {
                            return Err(Protocol {
                                source: ProtocolError::new(
                                    ErrorType::InvalidTransactionData,
                                    Some("Error validating transaction data hashes".to_string()),
                                    None,
                                ),
                            });
                        }
                    }
                }
            }

            // When holder sends transaction data hashes but verifier doesn't expect them. That case was not specified or mentioned how to handle in the specification
            // https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-transaction-data
            _ => {}
        }

        Ok(())
    }
    async fn resolve_did_and_jwk_from_id_token_header(
        &self,
        header: ssi::claims::jws::Header,
    ) -> Result<(String, ssi::jwk::JWK)> {
        let Some(kid) = header.key_id else {
            IdTokenValidationSnafu {
                details: "header must contain 'kid' claim",
            }
            .fail()?
        };

        let did_url = DIDURLBuf::from_string(kid).context(DidUrlResolutionSnafu)?;
        let jwk = self
            .public_jwk_resolver
            .fetch_public_jwk(Some(did_url.as_str()))
            .await
            .map_err(|e| {
                ParseSnafu {
                    details: format!("could not resolve public jwk from did_url: {e}"),
                }
                .build()
            })?;

        Ok((did_url.did().to_string(), jwk.deref().to_owned()))
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn build_authorization_request(
        &self,
        resolved_presentation_query: &ResolvedPresentationQuery,
        nonce: Nonce,
        wallet_metadata: &WalletMetadata,
        auth_request_metadata: &AuthorizationRequestMetadata,
    ) -> Result<(Url, Option<String>)> {
        match &auth_request_metadata.auth_response_options.mode {
            ResponseMode::FragmentJwt | ResponseMode::Fragment => {
                let client = RedirectUriClient::new(self.metadata.client_id.get_id())
                    .context(ClientSnafu)?;
                let verifier_builder = openid4vp::verifier::Verifier::builder().with_client(client);
                self.build_authorization_request_helper(
                    resolved_presentation_query,
                    nonce,
                    wallet_metadata,
                    verifier_builder,
                    auth_request_metadata,
                )
                .await
            }
            _ => {
                info!("access to the key {}", self.metadata.key_metadata.kid);
                let verifier_key = self
                    .kms
                    .get(&self.metadata.key_metadata.kid)
                    .await
                    .context(KMSSnafu)?;

                let did_client = DecentralizedIdentifierClient::new(
                    self.metadata.key_metadata.did_url.clone(),
                    Signer::new(verifier_key)?,
                    &self.public_jwk_resolver,
                )
                .await
                .context(Oid4VpLibSnafu)?;

                let verifier_builder =
                    openid4vp::verifier::Verifier::builder().with_client(did_client);
                self.build_authorization_request_helper(
                    resolved_presentation_query,
                    nonce,
                    wallet_metadata,
                    verifier_builder,
                    auth_request_metadata,
                )
                .await
            }
        }
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn build_authorization_request_helper(
        &self,
        resolved_presentation_query: &ResolvedPresentationQuery,
        nonce: Nonce,
        wallet_metadata: &WalletMetadata,
        verifier_builder: openid4vp::verifier::VerifierBuilder<
            impl openid4vp::verifier::client::Client + WasmNotSend + WasmNotSync,
        >,
        auth_request_metadata: &AuthorizationRequestMetadata,
    ) -> Result<(Url, Option<String>)> {
        let auth_req_type = match auth_request_metadata.pass_auth_request_object.to_owned() {
            PassAuthRequestObject::ByValue => {
                let response_mode = &auth_request_metadata.auth_response_options.mode;
                if response_mode == &ResponseMode::FragmentJwt
                    || response_mode == &ResponseMode::Fragment
                {
                    RequestType::Plain
                } else {
                    RequestType::SignedJwt(ByReference::False)
                }
            }
            PassAuthRequestObject::ByReference { uri, method } => {
                RequestType::SignedJwt(ByReference::True(RequestReference {
                    request_uri: uri,
                    request_uri_method: method,
                }))
            }
        };
        let verifier_builder =
            if let Some(uri) = &auth_request_metadata.auth_response_options.submission_uri {
                verifier_builder.with_submission_endpoint(uri.to_owned())
            } else {
                verifier_builder
            };

        let verifier = verifier_builder.build().await.context(Oid4VpLibSnafu)?;

        let request_builder = verifier.build_authorization_request();

        let request_builder = match auth_request_metadata.auth_response_options.type_ {
            ResponseType::VpTokenIdToken => request_builder
                .with_request_parameter(
                    auth_request_metadata.auth_response_options.type_.to_owned(),
                )
                .with_request_parameter(Scope("openid".to_string()))
                .with_request_parameter(IdTokenType::SubjectSigned),
            _ => request_builder.with_request_parameter(
                auth_request_metadata.auth_response_options.type_.to_owned(),
            ),
        };

        let mut request_builder = match &auth_request_metadata.auth_response_options.state {
            Some(state) => request_builder.with_request_parameter(State(state.to_string())),
            None => request_builder,
        };

        match resolved_presentation_query {
            ResolvedPresentationQuery::PresentationDefinition(pd) => {
                request_builder = request_builder.with_presentation_definition(pd.clone());
            }
            ResolvedPresentationQuery::DCQL(dcql) => {
                request_builder = request_builder.with_dcql(dcql.clone());
            }
        }
        if let Some(td) = &auth_request_metadata.transaction_data {
            let mut td_items = Vec::new();
            for item in td {
                td_items.push(item.clone().into_base64url_encoded()?)
            }
            request_builder = request_builder.with_request_parameter(TransactionData(td_items));
        }

        request_builder = match &auth_request_metadata.expected_origins {
            Some(origins) => request_builder.with_request_parameter(origins.to_owned()),
            _ => request_builder,
        };

        let (auth_request_url, auth_req_jwt) = request_builder
            .with_request_parameter(auth_request_metadata.auth_response_options.mode.to_owned())
            .with_request_parameter(NonceSpruce::from(nonce.secret()))
            .with_request_parameter(self.metadata.client_metadata.clone())
            .build(wallet_metadata, auth_req_type)
            .await?;

        Ok((auth_request_url, auth_req_jwt))
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn do_verify_presentation(
        &self,
        resolved_presentation_query: &ResolvedPresentationQuery,
        nonce: &Nonce,
        authorization_response: &AuthorizationResponseObject,
        presentation_verification_opts: PresentationVerificationOptions,
    ) -> Result<(Claim, HashMap<String, Vec<crate::vc::Presentation>>)> {
        let mut result: HashMap<String, Vec<Claim>> = HashMap::new();
        let mut presentations: HashMap<String, Vec<crate::vc::Presentation>> = HashMap::new();
        let mut ids = vec![]; // we need it to preserve order of items in the array
        let requested_presentations = match resolved_presentation_query {
            ResolvedPresentationQuery::DCQL(dcql) => dcql::resolve_presentation_response(
                authorization_response.vp_token.clone(),
                dcql,
                &presentation_verification_opts,
            )
            .context(DCQLSnafu)?,
            ResolvedPresentationQuery::PresentationDefinition(pd) => {
                let ps = authorization_response
                    .presentation_submission
                    .clone()
                    .ok_or_else(|| Protocol {
                        source: ProtocolError::invalid_request(
                            "Invalid Authorization response, 'presentation_submission' is not provided",
                            None,
                        ),
                    })?;

                let presentation_response = PresentationResponse {
                    presentations: authorization_response.vp_token.clone(),
                    presentation_submission: ps,
                };
                presentation_exchange::resolve_presentation_response(&presentation_response, pd)
                    .context(PresentationExchangeSnafu)?
            }
        };

        for requested_presentation in requested_presentations {
            let holder_binder =
                if let Some(false) = requested_presentation.require_cryptographic_holder_binding {
                    None
                } else {
                    Some(HolderBinder {
                        nonce: nonce.to_owned(),
                        verifier_id: presentation_verification_opts
                            .audience
                            .as_deref()
                            .unwrap_or(&self.metadata.client_id.get_full_id())
                            .to_owned(),
                    })
                };

            let claims = self
                .verifier
                .verify_presentation(
                    holder_binder,
                    &requested_presentation.presentation,
                    &self.http_client,
                )
                .await
                .context(VCSnafu)?;

            let id = requested_presentation.id;
            ids.push(id.clone());
            result
                .entry(id.clone())
                .and_modify(|arr| {
                    arr.push(claims.clone().into());
                })
                .or_insert(vec![claims.into()]);
            presentations
                .entry(id)
                .or_default()
                .push(requested_presentation.presentation);
        }

        Self::validate_against_requested_claims(
            resolved_presentation_query,
            authorization_response,
            &result,
            ids,
        )?;

        let result = HashMap::from_iter(result.into_iter().map(|(k, v)| (k, Claim::Array(v))));
        Ok((Claim::Object(result), presentations))
    }

    fn validate_against_requested_claims(
        resolved_presentation_query: &ResolvedPresentationQuery,
        authorization_response: &AuthorizationResponseObject,
        credentials: &HashMap<String, Vec<Claim>>,
        ids: Vec<String>,
    ) -> Result<()> {
        match resolved_presentation_query {
            ResolvedPresentationQuery::PresentationDefinition(pd) => {
                match authorization_response.vp_token {
                    Json::Array(_) => {
                        let mut claims: Vec<Value> = vec![];
                        for id in ids.into_iter() {
                            for c in credentials.get(&id).unwrap() {
                                claims.push(c.clone().try_into().context(ClaimsSnafu)?);
                            }
                        }

                        let claims = Json::Array(claims);
                        validate_against_presentation_definition(
                            &claims,
                            pd,
                            &authorization_response
                                .clone()
                                .presentation_submission
                                .unwrap(),
                        )
                        .context(PresentationExchangeSnafu)?;
                    }
                    _ => {
                        if let Some(claim) = credentials.values().next().and_then(|c| c.first()) {
                            // TODO: figure out how to secure erase sensitive data
                            // after Claim -> Value convertation
                            validate_against_presentation_definition(
                                &claim.clone().try_into().context(ClaimsSnafu)?,
                                pd,
                                &authorization_response
                                    .clone()
                                    .presentation_submission
                                    .unwrap(),
                            )
                            .context(PresentationExchangeSnafu)?;
                        }
                    }
                }
            }
            ResolvedPresentationQuery::DCQL(dcql) => {
                validate_credentials(dcql, credentials).context(DCQLSnafu)?
            }
        };
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::MockHttpClient;
    use crate::inmem::kms::LocalKms;
    use crate::nonce::Nonce;
    use crate::vc::ClaimFormatDesignation;
    use crate::vc::claims::Claims;
    use crate::vc::dcql::DCQLCredential;
    use crate::vc::formats::mso_mdoc::tests::SAMPLE_MSO_MDOC_VP;
    use crate::vc::oid4vp::jwe::JweEncryptor;
    use crate::vc::oid4vp::tests::fixtures::multi_presentation::{
        auth_response_options, submission_requirements, transaction_data_items,
    };
    use crate::vc::oid4vp::tests::fixtures::{NONCE, multi_presentation, single_presentation};
    use crate::vc::oid4vp::tests::fixtures::{STATE, VERIFIER_URL};
    use crate::vc::oid4vp::tests::utils::{
        VerificationTestCase, build_url, generate_client_metadata, validate_claims,
        verifier_service, verifier_service_with_invalid_kid, verifier_service_with_signer_error,
    };
    use crate::vc::oid4vp::verifier::VP_TOKEN;
    use crate::vc::oid4vp::{ExpectedOrigins, HttpMethodForAuth, InternalError};
    use crate::vc::oid4vp::{PassAuthRequestObject, PresentationSession, ResponseType, Verifier};
    use crate::vc::presentation_exchange::PresentationDefinition;
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use openid4vp::core::authorization_request::{
        AuthorizationRequest, AuthorizationRequestObject,
    };
    use openid4vp::core::dcql::{DCQL, DcqlClaim, DcqlCredential, DcqlMeta, ID, PathValue};
    use openid4vp::core::object::UntypedObject;
    use openid4vp::utils::NonEmptyVec;
    use openid4vp::wallet::IdTokenParams;
    use rstest::*;
    use serde_json::{Map, json};
    use ssi::claims::jwt::decode_unverified;
    use std::collections::HashMap;
    use url::Url;

    #[tokio::test]
    async fn generate_auth_request_by_reference_success() {
        let presentation_definition = single_presentation::sd_jwt::presentation_definition();
        let request_uri = build_url(VERIFIER_URL, "request");
        let request_uri_method = "post";

        let (verifier, client_id) = verifier_service().await;

        let auth_response_options = auth_response_options(build_url(VERIFIER_URL, "auth"), None);

        let (uri, _) = verifier
            .create_authorization_request(
                &presentation_definition,
                &AuthorizationRequestMetadata {
                    auth_response_options,
                    transaction_data: None,
                    pass_auth_request_object: PassAuthRequestObject::ByReference {
                        uri: request_uri.clone(),
                        method: Some(HttpMethodForAuth::POST),
                    },
                    expected_origins: None,
                },
                None,
            )
            .await
            .unwrap();

        let hash_query: HashMap<String, String> = uri.query_pairs().into_owned().collect();

        assert_eq!(hash_query.get("client_id").unwrap(), &client_id);
        assert_eq!(hash_query.get("request_uri").unwrap(), request_uri.as_str());
        assert_eq!(
            hash_query.get("request_uri_method").unwrap(),
            request_uri_method
        );
    }

    #[rstest]
    #[case::plain_dc_api_response_mode(ResponseMode::DcApi)]
    #[case::encrypted_dc_api_jwt_response_mode(ResponseMode::DcApiJwt)]
    #[tokio::test]
    async fn generate_signed_auth_request_with_dc_api_response_mode_success(
        #[case] response_mode: ResponseMode,
    ) {
        let request_uri = build_url(VERIFIER_URL, "request");

        let (verifier, did) = verifier_service().await;
        let mut auth_response_options =
            auth_response_options(build_url(VERIFIER_URL, "auth"), None);
        auth_response_options.mode = response_mode;

        let expected_origins = vec![Url::parse("https://example.verifier.org").unwrap().origin()];

        let (url, session) = verifier
            .create_authorization_request(
                &ResolvedPresentationQuery::DCQL(DCQL::new(sample_dcql())),
                &AuthorizationRequestMetadata {
                    transaction_data: None,
                    auth_response_options,
                    pass_auth_request_object: PassAuthRequestObject::ByValue,
                    expected_origins: Some(ExpectedOrigins::new(
                        expected_origins.clone().try_into().unwrap(),
                    )),
                },
                None,
            )
            .await
            .unwrap();

        let request: AuthorizationRequestObject =
            decode_unverified::<UntypedObject>(session.auth_request_jwt.unwrap().as_str())
                .unwrap()
                .try_into()
                .unwrap();

        assert_eq!(
            request.expected_origins().unwrap().origins().to_vec(),
            expected_origins
        );
    }

    #[tokio::test]
    async fn auth_request_generating_fails_when_key_id_is_not_valid() {
        let presentation_definition = single_presentation::sd_jwt::presentation_definition();
        let request_uri = build_url(VERIFIER_URL, "request");
        let auth_response_options = auth_response_options(build_url(VERIFIER_URL, "auth"), None);

        let (verifier, did) = verifier_service_with_invalid_kid().await;

        let result = verifier
            .create_authorization_request(
                &presentation_definition,
                &AuthorizationRequestMetadata {
                    transaction_data: None,
                    auth_response_options,
                    pass_auth_request_object: PassAuthRequestObject::ByReference {
                        uri: request_uri,
                        method: None,
                    },
                    expected_origins: None,
                },
                None,
            )
            .await;

        assert!(matches!(
            result.err().unwrap(),
            Internal {
                source: InternalError::KMS { .. }
            }
        ));
    }

    #[tokio::test]
    async fn auth_request_generating_fails_in_case_of_signer_error() {
        let presentation_definition = single_presentation::sd_jwt::presentation_definition();
        let request_uri = build_url(VERIFIER_URL, "request");
        let auth_response_options = auth_response_options(build_url(VERIFIER_URL, "auth"), None);

        let (verifier, did) = verifier_service_with_signer_error().await;

        let result = verifier
            .create_authorization_request(
                &presentation_definition,
                &AuthorizationRequestMetadata {
                    transaction_data: None,
                    auth_response_options,
                    pass_auth_request_object: PassAuthRequestObject::ByReference {
                        uri: request_uri,
                        method: None,
                    },
                    expected_origins: None,
                },
                None,
            )
            .await;

        assert!(matches!(
            result.err().unwrap(),
            Internal {
                source: InternalError::Oid4VpLib { .. }
            }
        ));
    }

    #[tokio::test]
    async fn generate_auth_request_by_value_success() {
        let presentation_definition = single_presentation::sd_jwt::presentation_definition();
        let response_uri: Url = build_url(VERIFIER_URL, "auth");

        let (verifier, client_id) = verifier_service().await;

        let auth_response_options = auth_response_options(response_uri.clone(), None);

        let transaction_data = &transaction_data_items();

        let (request_uri, session) = verifier
            .create_authorization_request(
                &presentation_definition,
                &AuthorizationRequestMetadata {
                    transaction_data: Some(transaction_data.to_owned()),
                    auth_response_options,
                    pass_auth_request_object: PassAuthRequestObject::ByValue,
                    expected_origins: None,
                },
                None,
            )
            .await
            .unwrap();

        let auth_request = AuthorizationRequest::from_query_params(request_uri.query().unwrap());

        let hash_query: HashMap<String, String> = request_uri.query_pairs().into_owned().collect();
        let auth_req_jwt_from_uri = hash_query.get("request").unwrap();

        let request: AuthorizationRequestObject =
            decode_unverified::<UntypedObject>(auth_req_jwt_from_uri)
                .unwrap()
                .try_into()
                .unwrap();

        let actual_presentation_definition = request
            .resolve_presentation_query(&MockHttpClient::new())
            .await
            .unwrap()
            .get_presentation_definition()
            .unwrap();

        let encoded_transaction_data1 = transaction_data.first().unwrap();
        let encoded_transaction_data2 = transaction_data.get(1).unwrap();
        let encoded1 = BASE64_URL_SAFE_NO_PAD
            .encode(serde_json::to_string(encoded_transaction_data1).unwrap());
        let encoded2 = BASE64_URL_SAFE_NO_PAD
            .encode(serde_json::to_string(encoded_transaction_data2).unwrap());
        assert_eq!(
            encoded1.as_str(),
            request
                .get_transaction_data()
                .unwrap()
                .0
                .first()
                .unwrap()
                .as_str()
        );
        assert_eq!(
            encoded2.as_str(),
            request
                .get_transaction_data()
                .unwrap()
                .0
                .get(1)
                .unwrap()
                .as_str()
        );

        assert_eq!(
            session.auth_request_jwt.unwrap(),
            auth_req_jwt_from_uri.to_owned()
        );
        assert_eq!(
            serde_json::to_value(&actual_presentation_definition).unwrap(),
            serde_json::to_value(
                presentation_definition
                    .get_presentation_definition()
                    .unwrap()
            )
            .unwrap()
        );
        assert_eq!(request.client_id().to_string(), client_id);
        assert_eq!(request.return_uri(), Some(&response_uri));
    }

    #[tokio::test]
    async fn generate_auth_request_with_state_success() {
        let presentation_definition = single_presentation::sd_jwt::presentation_definition();
        let response_uri: Url = build_url(VERIFIER_URL, "auth");

        let (verifier, did) = verifier_service().await;

        let auth_response_options =
            auth_response_options(response_uri.clone(), Some(STATE.to_string()));

        let (request_uri, session) = verifier
            .create_authorization_request(
                &presentation_definition,
                &AuthorizationRequestMetadata {
                    transaction_data: None,
                    auth_response_options,
                    pass_auth_request_object: PassAuthRequestObject::ByValue,
                    expected_origins: None,
                },
                None,
            )
            .await
            .unwrap();

        let auth_request = AuthorizationRequest::from_query_params(request_uri.query().unwrap());

        let hash_query: HashMap<String, String> = request_uri.query_pairs().into_owned().collect();
        let auth_req_jwt_from_uri = hash_query.get("request").unwrap();

        let request: AuthorizationRequestObject =
            decode_unverified::<UntypedObject>(auth_req_jwt_from_uri)
                .unwrap()
                .try_into()
                .unwrap();
        let state = request.get::<State>().unwrap().unwrap();

        assert_eq!(state.0, STATE);
    }

    #[tokio::test]
    async fn generate_siop_auth_request_by_value_success() {
        let presentation_definition = single_presentation::sd_jwt::presentation_definition();
        let response_uri: Url = build_url(VERIFIER_URL, "auth");

        let (verifier, client_id) = verifier_service().await;

        let mut auth_response_options = auth_response_options(response_uri.clone(), None);
        auth_response_options.type_ = ResponseType::VpTokenIdToken;

        let (request_uri, session) = verifier
            .create_authorization_request(
                &presentation_definition,
                &AuthorizationRequestMetadata {
                    transaction_data: None,
                    auth_response_options,
                    pass_auth_request_object: PassAuthRequestObject::ByValue,
                    expected_origins: None,
                },
                None,
            )
            .await
            .unwrap();

        let auth_request = AuthorizationRequest::from_query_params(request_uri.query().unwrap());

        let hash_query: HashMap<String, String> = request_uri.query_pairs().into_owned().collect();
        let auth_req_jwt_from_uri = hash_query.get("request").unwrap();

        let request: AuthorizationRequestObject =
            decode_unverified::<UntypedObject>(auth_req_jwt_from_uri)
                .unwrap()
                .try_into()
                .unwrap();

        let actual_presentation_definition = request
            .resolve_presentation_query(&MockHttpClient::new())
            .await
            .unwrap()
            .get_presentation_definition()
            .unwrap();
        assert_eq!(
            session.auth_request_jwt.unwrap(),
            auth_req_jwt_from_uri.to_owned()
        );
        assert_eq!(
            serde_json::to_value(&actual_presentation_definition).unwrap(),
            serde_json::to_value(
                presentation_definition
                    .get_presentation_definition()
                    .unwrap()
            )
            .unwrap()
        );
        assert_eq!(request.client_id().to_string(), client_id);
        assert_eq!(request.return_uri(), Some(&response_uri));
        assert_eq!(
            request.get::<Scope>().unwrap().unwrap(),
            Scope("openid".to_string())
        );
        assert_eq!(
            request.get::<IdTokenType>().unwrap().unwrap(),
            IdTokenType::SubjectSigned
        );
    }

    // TODO: Validations will be implemented as part of the ASDK-98 task
    #[rstest]
    #[case::empty_id(presentation_definition_with_empty_id())]
    #[case::empty_descriptors(presentation_definition_with_empty_descriptors())]
    #[tokio::test]
    #[should_panic]
    async fn generate_auth_request_fails_on_invalid_presentation_def(
        #[case] presentation_definition: PresentationDefinition,
    ) {
        let request_uri = build_url(VERIFIER_URL, "request");

        let (verifier, did) = verifier_service().await;

        let auth_response_options = auth_response_options(build_url(VERIFIER_URL, "auth"), None);

        let (request, _) = verifier
            .create_authorization_request(
                &ResolvedPresentationQuery::PresentationDefinition(presentation_definition),
                &AuthorizationRequestMetadata {
                    transaction_data: None,
                    auth_response_options,
                    pass_auth_request_object: PassAuthRequestObject::ByReference {
                        uri: request_uri,
                        method: None,
                    },
                    expected_origins: None,
                },
                None,
            )
            .await
            .unwrap();
    }

    #[rstest]
    #[should_panic(expected = "Credential IDs must be unique in the dcql query")]
    #[case(get_multiple_credentials_with_same_id())]
    #[should_panic(expected = "Claim set cannot be given if Claims is empty")]
    #[case(get_credential_with_claim_set_but_no_claims())]
    #[should_panic(expected = "Claim id cannot be empty if Claim set is given")]
    #[case(get_credential_with_claim_set_but_no_claim_ids())]
    #[should_panic(expected = " Claim IDs must be unique in the Credential query")]
    #[case(get_credential_with_claims_with_non_unique_claim_ids())]
    #[tokio::test]
    async fn test_request_validation(#[case] credentials: NonEmptyVec<DcqlCredential>) {
        let request_uri = build_url(VERIFIER_URL, "request");

        let (verifier, did) = verifier_service().await;

        let auth_response_options = auth_response_options(build_url(VERIFIER_URL, "auth"), None);

        let dcql = DCQL::new(credentials);
        verifier
            .create_authorization_request(
                &ResolvedPresentationQuery::DCQL(dcql),
                &AuthorizationRequestMetadata {
                    transaction_data: None,
                    auth_response_options,
                    pass_auth_request_object: PassAuthRequestObject::ByReference {
                        uri: request_uri,
                        method: None,
                    },
                    expected_origins: None,
                },
                None,
            )
            .await
            .unwrap();
    }

    #[rstest]
    #[case::single_presentation_success(single_presentation::sd_jwt::verification_test_case())]
    #[case::multi_presentation_success(multi_presentation::verification_test_case())]
    #[case::multi_presentation_success(submission_requirements_satisfied_case())]
    #[tokio::test]
    async fn verify_auth_response_success(#[case] test_case: VerificationTestCase) {
        let (verifier, client_id) = verifier_service().await;
        let session = PresentationSession {
            nonce: Nonce::from_secret(NONCE.to_owned()),
            resolved_presentation_query: test_case.session.resolved_presentation_query.clone(),
            auth_request_jwt: Default::default(),
        };

        let response = test_case
            .auth_response_with_transaction_data_response(&session.nonce, &client_id)
            .await;

        let verified_claims = verifier
            .verify_presentation(
                &AuthorizationResponse::Plain(response),
                &test_case.session,
                &CredentialVerificationMetadata {
                    transaction_data: Some(transaction_data_items()),
                    audience: None,
                },
            )
            .await
            .unwrap();

        validate_vp_token_against_expected_claims(test_case, &verified_claims);
    }

    #[tokio::test]
    #[should_panic(expected = "Transaction data hashes were not provided but were expected")]
    async fn verifier_validating_transaction_data_returns_error() {
        let test_case = single_presentation::sd_jwt::verification_test_case();
        let (verifier, client_id) = verifier_service().await;
        let session = PresentationSession {
            nonce: Nonce::from_secret(NONCE.to_owned()),
            resolved_presentation_query: test_case.session.resolved_presentation_query.clone(),
            auth_request_jwt: Default::default(),
        };
        let response = test_case
            .auth_response_without_transaction_data_response(&session.nonce, &client_id)
            .await;

        let verified_claims = verifier
            .verify_presentation(
                &AuthorizationResponse::Plain(response),
                &test_case.session,
                &CredentialVerificationMetadata {
                    transaction_data: Some(transaction_data_items()),
                    audience: None,
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn verifier_validating_mso_mdoc_vp_works_correctly() {
        let (verifier, _) = verifier_service().await;
        let session = PresentationSession {
            nonce: Nonce::from_secret("4Y1DVuoVHfjotxmX55AQv36Tr5sdcvaBLXia6bj2hUM".to_string()),
            resolved_presentation_query: ResolvedPresentationQuery::DCQL(
                sample_dcql_query_for_mso_mdoc_vp_request(),
            ),
            auth_request_jwt: Default::default(),
        };
        let mut vp_token = HashMap::new();
        vp_token.insert(
            "mDL",
            Value::Array(vec![Value::String(SAMPLE_MSO_MDOC_VP.to_string())]),
        );

        let response = AuthorizationResponseObject {
            vp_token: serde_json::to_value(vp_token).unwrap(),
            presentation_submission: None,
            id_token: None,
            state: None,
            transaction_data_response: None,
        };

        let verified_claims = verifier
            .verify_presentation(
                &AuthorizationResponse::Plain(response),
                &session,
                &CredentialVerificationMetadata {
                    transaction_data: None,
                    audience: Some("https://embedui.ssi.dev.dsr.gaminghub.bc-labs.dev".to_string()),
                },
            )
            .await
            .unwrap();

        let claims = &verified_claims["vp_token"]["mDL"].as_vec().unwrap()[0]["org.iso.18013.5.1"];
        assert_eq!(claims["family_name"].as_str(), Some("Mustermann"));
        assert_eq!(claims["given_name"].as_str(), Some("Erika"));
    }

    #[tokio::test]
    #[should_panic(expected = "Error validating transaction data hashes")]
    async fn verifier_validating_transaction_data_returns_validation_error() {
        let test_case = single_presentation::sd_jwt::verification_test_case();
        let (verifier, client_id) = verifier_service().await;
        let session = PresentationSession {
            nonce: Nonce::from_secret(NONCE.to_owned()),
            resolved_presentation_query: test_case.session.resolved_presentation_query.clone(),
            auth_request_jwt: Default::default(),
        };
        let response = test_case
            .auth_response_with_wrong_transaction_data_response(&session.nonce, &client_id)
            .await;

        let verified_claims = verifier
            .verify_presentation(
                &AuthorizationResponse::Plain(response),
                &test_case.session,
                &CredentialVerificationMetadata {
                    transaction_data: Some(transaction_data_items()),
                    audience: None,
                },
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn verify_auth_response_with_id_token_success() {
        let test_case = single_presentation::sd_jwt::verification_test_case();
        let (verifier, client_id) = verifier_service().await;
        let kms = LocalKms::new();
        let session = PresentationSession {
            nonce: Nonce::from_secret(NONCE.to_owned()),
            resolved_presentation_query: test_case.session.resolved_presentation_query.clone(),
            auth_request_jwt: Default::default(),
        };

        let id_token_params = IdTokenParams {
            audience: client_id.to_owned(),
            nonce: session.nonce.secret().to_owned().into(),
            lifetime: time::Duration::minutes(5),
            other: None,
        };
        let response = test_case
            .auth_response_with_id_token(&session.nonce, &client_id, id_token_params)
            .await;

        let verified_claims = verifier
            .verify_presentation(
                &AuthorizationResponse::Plain(response),
                &test_case.session,
                &CredentialVerificationMetadata::default(),
            )
            .await
            .unwrap();

        validate_vp_token_against_expected_claims(test_case, &verified_claims);

        let id_token_claims: IdToken =
            serde_json::from_value(verified_claims[ID_TOKEN].to_owned().try_into().unwrap())
                .unwrap();
        assert_eq!(id_token_claims.audience, client_id);
        assert_eq!(id_token_claims.nonce, session.nonce.secret());
    }

    #[rstest]
    #[should_panic(expected = "Invalid nonce")]
    #[case::invalid_nonce(invalid_nonce_case())]
    #[should_panic(
        expected = "Requested presentation SD_JWT_cred not found in the presentation submission"
    )]
    #[case::presentation_not_provided(presentation_not_provided_case())]
    #[should_panic(
        expected = "Requested presentation Identity-1 not found in the presentation submission"
    )]
    #[case::empty_descriptor_map(empty_descriptor_map_case())]
    #[should_panic(
        expected = "presentation submission validation failed: missing required input `Identity-1"
    )]
    #[case::invalid_presentation_type(presentation_with_different_claim_values_case())]
    #[should_panic(
        expected = "presentation submission validation failed: missing required input `Identity-1`"
    )]
    #[case::presentation_claim_not_found(presentation_claim_not_found_case())]
    #[should_panic(expected = "invalid number of inputs for group `A` (expected 2, found 1)")]
    #[case::submission_requirements_unsatisfied(submission_requirements_unsatisfied_case())]
    #[tokio::test]
    async fn verify_auth_response_fails(#[case] test_case: VerificationTestCase) {
        let (verifier, client_id) = verifier_service().await;
        let nonce = Nonce::from_secret(NONCE.to_owned());

        let response = test_case
            .auth_response_with_transaction_data_response(&nonce, &client_id)
            .await;

        let verified_claims = verifier
            .verify_presentation(
                &AuthorizationResponse::Plain(response),
                &test_case.session,
                &CredentialVerificationMetadata::default(),
            )
            .await
            .unwrap();
    }

    #[rstest]
    #[should_panic(expected = "incorrect nonce")]
    #[case::incorrect_nonce(Some("invalid".to_string()), None, None)]
    #[should_panic(expected = "id token audience value mismatch")]
    #[case::invalid_audience(None, Some("did:example:1234".to_string(),), None)]
    #[should_panic(expected = "id token is expired")]
    #[case::token_expired(None, None, Some(time::Duration::seconds(0)))]
    #[tokio::test]
    async fn verify_auth_response_fails_on_invalid_vp_token(
        #[case] nonce: Option<String>,
        #[case] audience: Option<String>,
        #[case] lifetime: Option<time::Duration>,
    ) {
        let test_case = single_presentation::sd_jwt::verification_test_case();
        let (verifier, client_id) = verifier_service().await;
        let session = PresentationSession {
            nonce: Nonce::from_secret(NONCE.to_owned()),
            resolved_presentation_query: test_case.session.resolved_presentation_query.clone(),
            auth_request_jwt: Default::default(),
        };

        let id_token_params = IdTokenParams {
            audience: audience.unwrap_or(client_id.to_owned()),
            nonce: nonce.unwrap_or(session.nonce.secret().to_owned()).into(),
            lifetime: lifetime.unwrap_or(time::Duration::minutes(5)),
            other: None,
        };
        let response = test_case
            .auth_response_with_id_token(&session.nonce, &client_id, id_token_params)
            .await;

        let verified_claims = verifier
            .verify_presentation(
                &AuthorizationResponse::Plain(response),
                &test_case.session,
                &CredentialVerificationMetadata::default(),
            )
            .await
            .unwrap();
    }

    const JWE: &str = "eyJraWQiOiJhYyIsImVuYyI6IkExMjhDQkMtSFMyNTYiLCJhbGciOiJFQ0RILUVTIiwiYXB1IjoiYzI5dFpWOXViMjVqWlEiLCJhcHYiOiJjMjl0WlY5dWIyNWpaUSIsImVwayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IjZIaGh4WVlxbU9uc2NDLVkwZVNOYXJEZ0w0SGp5WW1BVXdJM3A2bkJ0eU0iLCJ5Ijoic3dYZ1BDbVdUR0RZSTJ6NGYtY2V5UE53dEhqRm9pNWZOY0Y0UTd2alNOYyJ9fQ..3zjOOJzGnCzYmEUp-xCgFA.CoDI0RyG7RV1K1oLb9jhqqMu-x55IWQFvQtFYsi3gzD1Shmb5o5TDWrnSX-66UZyHt_2yl0syKXDN557WUpazwRLckKituanU6fx0BFUARb0vyDnbHSvMNrLtJpfq7-pcsGqCg-6kCBNRV9NsvKrDyYqzlekyiAjO5eFR2fQ7x9r2IgI3kNZP9So6ZeQV5tESyiX5aX2sxPpplx9UlBquyTgLwWxfPvriuWuEwB09GmaEV9hSrfHTclZ-Pleltxjw3bKmm17gA1TzUhnjpw6GptkieVwWFplQO9xjyWV05V0EnaDZGeHpH2sGaA_uURXgei4V6YHjHq_Qor9LOY030OGNZr5VGEnD1UTCZlC__uzRGneBSGM_KqypBubGDS4DxrefF7AdRu1eDc1Gx846_9qgwT3K8bzI36pUGROboPCosJ2-l5_ICSghKqZJYUUubDOZpgLopPXQRwxSg84VGKlPs2U04JnhDlZkmGD5gNd3RKi1De5_2DfYxFyBJXF-mB8V4rWU3XwW1hcqD8ErY_1-vWa8oaxy7CoW7M0swdxza66xBuC8Rh2hVY6XNHpVltnG2RzViuZH2OYyPJ0O74uiuvneSjob7qpSi-jvfXHwDzWqu9te-mJT_3wk0MEFIVg3g8YZ6HBzDlOxEea_9aHwDpTz43-KEy5nfYvR_GTh0Tg-mu2qq-IZCBUnZQ1qtDGKBg-ixa9F7BNVz7Tcxc2UDaaByUjbGmQVTvYX2cuf2HFTqrQ4wYWws2fvMS0F9fjUQOL9dDvexdhqn7_raGN8zUSNsjW6tOubIayTXpgXCz4HvNLwZElh_fMK8Gb-5LAQcROzbkgECxT0LZcgFIBiMJbKAeAc8k0XyFek4f7MMMz6qCjQdZOrtrovGTLSIuUaB3cLVbrpq-JYKhwocn-iH6Bm_SLeTd5LjqMdLsDaXTNHvjXMPK1QT8ikSI846G1GvFBeL7Vek9q6t4pD18YuMsY7w9__V4az9KguWpZsJrULj7at831DGZfh0pa25Z_VdDKOjppb-j3ceROTolYCaZSTPrWyrDA_9cOjuKF_iF8bMbd2nGzmOHUd-tz096dcPUMJ9hets2cIU_8XOAoYYtTNCP3tXoP2ovLKptZsnuJsJuIgcP3kiQhuK05m8sfkMRRrJKci7wk6StbUHcO73v5olviO3ALDOZ5CsuAQeWO00BKTyjpNloeHt7t6gOEHM38gfebSIVNGxuWrrs0YL-VGcfDB91o7Cm8FScj0Qv_d0NT4snP46OBRQAaJdrX0_UBoxYhOyZQTBOzzhMXfuhMqn_NZuieglGqOUP25iexsaZPC8S4l-2HSFPv8m4t07GVgRW881XykozSR2L1CDz_JIsDtrVCEVWG-tnxVn4-1Lrt4VUhZOOrdqvjD9MkikX_Gysplmw0vMoS_26esWFAXhqtaRHlwAaoDoc8XmD_tvNiaPErj34imEFNBVffeyBHegA4WU_WydtA7MUOEt0xjO3hgUbRoAYB7w4c5Z94QFwOKC2IZl2Aj2Bz_r4LTESGpnUYd7810yJp_4PHpeAkE4LBmNaM5b1t_UVOnk7lkpnNOtXqqzeg_rdvzXhLjc-WyZvdNQt2m4LW6qpjNLBZ3jrrmZbeurQ2aqtDnnG2cjAxStpV7QJ16XRu6WPWamTriIMlEJfh7XzTREHd0TW79Kdk4fUTgzC1I1csKygh11e6-F3RI0xtXqsOd_k-uc-F6LNeIziQftaQeDY79XUpZed8xqJ5d9xIyrb2L9fHucPthg5btXeRrTNUaD76j6U-fewRRwdh1mWqmDIfIHmWzBRWAmMyFoUKDZKtDfz-iZPV_2I5RWbn6Jx3M02zEk6UCnH7t8IWT5aug02takkHRnEvD8ZNGljLs00MZjoe89Sz-Z0zPIJ-sXGIKXIbZITuU5H4yi7D6RLBDfZpRZPBJBjlFtF0WXlkItvaqQrUU31QLPRir73aTvTY6kKOGKfyg1BdLTtNyVoWJ7tbMTZH2UlJ8G8AA5X_gQQ0aD6mgdKCef0eha5NBQyJ-ATqSPhh1DD9RnWic2-CugNrIDhmFpcl8nDBfVokoNZsTWz62Pin9Cztp1f41T4T.jQWuxtlpSXrokaAhm440gQ";

    #[rstest]
    #[should_panic(expected = "Error while getting the jwe header")]
    #[case("not_even_jwt")]
    #[should_panic(expected = "Error while getting the key handle for ac")]
    #[case(JWE)]
    #[tokio::test]
    async fn resolve_authorization_response_jwe_negative(#[case] jwt: &str) {
        let (verifier, _) = verifier_service().await;

        let result = verifier
            .resolve_authorization_response(&AuthorizationResponse::Jwe(jwt.to_owned()))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Error while getting the key handle")]
    async fn resolve_authorization_response_jwe_wrong_kid() {
        let (verifier, did) = verifier_service().await;
        let test_case = single_presentation::sd_jwt::verification_test_case();

        let wrong_kid = "wrong-kid";
        let wrong_kid_metadata = generate_client_metadata(&LocalKms::new()).await;
        let encryptor = JweEncryptor::new(wrong_kid_metadata);
        let jwt = encryptor
            .encrypt(serde_json::to_value("{\"WRONG\":\"PAYLOAD\"}").unwrap())
            .await
            .unwrap();

        let result = verifier
            .resolve_authorization_response(&AuthorizationResponse::Jwe(jwt.to_owned()))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Error: The claim set must be an object")]
    async fn resolve_authorization_response_jwe_no_claims() {
        let (verifier, did) = verifier_service().await;
        let test_case = single_presentation::sd_jwt::verification_test_case();

        let encryptor = JweEncryptor::new(verifier.metadata.client_metadata.clone());
        let jwt = encryptor
            .encrypt(serde_json::to_value("{\"WRONG\":\"PAYLOAD\"}").unwrap())
            .await
            .unwrap();

        verifier
            .resolve_authorization_response(&AuthorizationResponse::Jwe(jwt.to_owned()))
            .await
            .unwrap();
    }

    #[tokio::test]
    #[should_panic(expected = "Error: vp_token was not found")]
    async fn resolve_authorization_response_jwe_no_vp_token() {
        let (verifier, did) = verifier_service().await;
        let test_case = single_presentation::sd_jwt::verification_test_case();

        let encryptor = JweEncryptor::new(verifier.metadata.client_metadata.clone());
        let mut body = Map::new();
        body.insert(
            "presentation_submission".to_string(),
            json!(test_case.presentation_submission),
        );
        let jwt = encryptor.encrypt(Value::Object(body)).await.unwrap();

        verifier
            .resolve_authorization_response(&AuthorizationResponse::Jwe(jwt.to_owned()))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn resolve_authorization_response_jwe_positive() {
        let (verifier, did) = verifier_service().await;
        let test_case = single_presentation::sd_jwt::verification_test_case();

        let encryptor = JweEncryptor::new(verifier.metadata.client_metadata.clone());
        let mut body = Map::new();
        body.insert(
            "vp_token".to_string(),
            json!(
                test_case
                    .vp_token(&test_case.session.nonce, did.as_str())
                    .await
            ),
        );
        body.insert(
            "presentation_submission".to_string(),
            json!(test_case.presentation_submission),
        );
        let jwt = encryptor.encrypt(Value::Object(body)).await.unwrap();

        verifier
            .resolve_authorization_response(&AuthorizationResponse::Jwe(jwt.to_owned()))
            .await
            .unwrap();
    }

    fn validate_vp_token_against_expected_claims(
        test_case: VerificationTestCase,
        verified_claims: &Claims,
    ) {
        for (index, credential_data) in test_case.credential_data.into_iter().enumerate() {
            let cred_id = &test_case
                .presentation_submission
                .descriptor_map()
                .get(index)
                .unwrap()
                .id;

            let cred_claims = verified_claims[VP_TOKEN][cred_id].clone();

            match cred_claims {
                Claim::Array(ref presentations) => {
                    for presentation in presentations {
                        match presentation {
                            Claim::Object(p) => validate_claims(
                                &ClaimFormatDesignation::SdJwtVc,
                                &Claims::from_map(p.to_owned()),
                                &credential_data,
                            ),
                            _ => panic!("Unexpected claim type"),
                        }
                    }
                }
                _ => panic!("cred_claims is not an array"),
            };
        }
    }

    fn presentation_definition_with_empty_id() -> PresentationDefinition {
        let mut presentation_definition = single_presentation::sd_jwt::presentation_definition()
            .get_presentation_definition()
            .unwrap()
            .to_owned();
        presentation_definition = PresentationDefinition::new(
            "".to_string(),
            presentation_definition
                .input_descriptors()
                .first()
                .unwrap()
                .to_owned(),
        );

        presentation_definition
    }

    fn presentation_definition_with_empty_descriptors() -> PresentationDefinition {
        let mut presentation_definition = single_presentation::sd_jwt::presentation_definition()
            .get_presentation_definition()
            .unwrap()
            .to_owned();
        presentation_definition.input_descriptors_mut().clear();

        presentation_definition
    }

    fn invalid_nonce_case() -> VerificationTestCase {
        let mut test_case = single_presentation::sd_jwt::verification_test_case();
        test_case.session.nonce = Nonce::from_secret("other-nonce".to_owned());
        test_case
    }

    fn empty_descriptor_map_case() -> VerificationTestCase {
        let mut test_case = single_presentation::sd_jwt::verification_test_case();
        test_case
            .presentation_submission
            .descriptor_map_mut()
            .clear();
        test_case
    }

    fn presentation_not_provided_case() -> VerificationTestCase {
        let mut test_case = single_presentation::sd_jwt::verification_test_case();
        test_case.session.resolved_presentation_query =
            ResolvedPresentationQuery::PresentationDefinition(
                multi_presentation::presentation_definition(),
            );
        test_case
    }

    fn presentation_with_different_claim_values_case() -> VerificationTestCase {
        let mut test_case = single_presentation::sd_jwt::verification_test_case();
        test_case.credential_data = vec![
            json!({
                "vct": "https://credentials.example.com/degree_credential",
                "name": "John",
                "degree": "Bachelor"
            })
            .try_into()
            .unwrap(),
        ];
        test_case
    }

    fn presentation_claim_not_found_case() -> VerificationTestCase {
        let mut test_case = single_presentation::sd_jwt::verification_test_case();
        test_case.credential_data = vec![
            json!({
                "vct": "https://credentials.example.com/identity_credential",
                "degree": "Bachelor"
            })
            .try_into()
            .unwrap(),
        ];
        test_case
    }

    fn submission_requirements_satisfied_case() -> VerificationTestCase {
        let mut test_case = multi_presentation::verification_test_case();
        let mut pd = test_case
            .clone()
            .session
            .clone()
            .resolved_presentation_query
            .get_presentation_definition()
            .unwrap()
            .clone()
            .set_submission_requirements(submission_requirements(1));
        if let Some(i) = pd.input_descriptors_mut().get_mut(0) {
            i.groups.push("A".to_string());
        }
        test_case.session.resolved_presentation_query =
            ResolvedPresentationQuery::PresentationDefinition(pd);
        test_case
    }

    fn submission_requirements_unsatisfied_case() -> VerificationTestCase {
        let mut test_case = submission_requirements_satisfied_case();
        let mut pd = test_case
            .session
            .resolved_presentation_query
            .get_presentation_definition()
            .unwrap()
            .clone();
        pd = pd.set_submission_requirements(submission_requirements(2));
        test_case.session.resolved_presentation_query =
            ResolvedPresentationQuery::PresentationDefinition(pd);

        test_case
    }
    fn get_credential_for_sd_jwt_without_meta() -> NonEmptyVec<DcqlCredential> {
        NonEmptyVec::new(DCQLCredential::new(
            ID::new("some_id".to_string()).unwrap(),
            ClaimFormatDesignation::SdJwtVc,
            DcqlMeta::new(),
        ))
    }
    fn get_credential_for_ldp_vc_without_meta() -> NonEmptyVec<DcqlCredential> {
        NonEmptyVec::new(DCQLCredential::new(
            ID::new("some_id".to_string()).unwrap(),
            ClaimFormatDesignation::LdpVc,
            DcqlMeta::new(),
        ))
    }

    fn get_multiple_credentials_with_same_id() -> NonEmptyVec<DcqlCredential> {
        let mut vec = get_credential_for_sd_jwt_without_meta();
        for item in get_credential_for_ldp_vc_without_meta() {
            vec.push(item);
        }
        vec
    }

    fn get_credential_with_claim_set_but_no_claims() -> NonEmptyVec<DcqlCredential> {
        NonEmptyVec::new(
            DCQLCredential::new(
                ID::new("some_id".to_string()).unwrap(),
                ClaimFormatDesignation::SdJwtVc,
                DcqlMeta::new().set_vct_values(NonEmptyVec::new("some_vct_value".to_string())),
            )
            .add_claim_set(NonEmptyVec::new("some_claim_id".to_string())),
        )
    }

    fn get_credential_with_claim_set_but_no_claim_ids() -> NonEmptyVec<DcqlCredential> {
        NonEmptyVec::new(
            DCQLCredential::new(
                ID::new("some_id".to_string()).unwrap(),
                ClaimFormatDesignation::SdJwtVc,
                DcqlMeta::new().set_vct_values(NonEmptyVec::new("some_vct_value".to_string())),
            )
            .set_claims(NonEmptyVec::new(DcqlClaim::new(NonEmptyVec::new(
                PathValue::Null,
            ))))
            .add_claim_set(NonEmptyVec::new("some_claim_id".to_string())),
        )
    }

    fn get_credential_with_claims_with_non_unique_claim_ids() -> NonEmptyVec<DcqlCredential> {
        NonEmptyVec::new(
            DCQLCredential::new(
                ID::new("some_id".to_string()).unwrap(),
                ClaimFormatDesignation::SdJwtVc,
                DcqlMeta::new().set_vct_values(NonEmptyVec::new("some_vct_value".to_string())),
            )
            .add_claim(
                DcqlClaim::new(NonEmptyVec::new(PathValue::Null))
                    .set_id(ID::new("some_id".to_string()).unwrap()),
            )
            .add_claim(
                DcqlClaim::new(NonEmptyVec::new(PathValue::Null))
                    .set_id(ID::new("some_id".to_string()).unwrap()),
            )
            .add_claim_set(NonEmptyVec::new("some_claim_id".to_string())),
        )
    }

    fn sample_dcql() -> NonEmptyVec<DcqlCredential> {
        NonEmptyVec::new(DCQLCredential::new(
            ID::new("some_id".to_string()).unwrap(),
            ClaimFormatDesignation::SdJwtVc,
            DcqlMeta::new().set_vct_values(NonEmptyVec::new("some_vct_value".to_string())),
        ))
    }

    pub fn sample_dcql_query_for_mso_mdoc_vp_request() -> DCQL {
        let desc: DCQLCredential = serde_json::from_value(json!(
            {
                "id": "mDL",
                "format": "mso_mdoc",
                "meta": {
                    "doctype_value": "org.iso.18013.5.1.mDL"
                },
                "claims": [
                    {
                        "path": ["org.iso.18013.5.1", "given_name"],
                        "path": ["org.iso.18013.5.1", "family_name"],
                    },
                ],
            }
        ))
        .unwrap();

        DCQL::new(NonEmptyVec::new(desc))
    }
}
