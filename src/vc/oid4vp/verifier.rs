use crate::vc::oid4vp::internal_error::IssuerNotTrustedSnafu;
use crate::vc::trust::issuer::{IssuerTrust, IssuerTrustMode, IssuerTrustOutcome};

/// vp_token claims, raw presentations by credential id, and the issuer trust of each credential.
type VerifiedPresentations = (
    Claim,
    HashMap<String, Vec<crate::vc::Presentation>>,
    Vec<IssuerTrust>,
);
use async_trait::async_trait;
use openid4vp::core::authorization_request::parameters::{
    Audience, HashAlgorithm, IdTokenType, Nonce as NonceSpruce, Scope, State, TransactionData,
};
use openid4vp::core::metadata::WalletMetadata;
use openid4vp::core::metadata::parameters::wallet::Issuer;
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
#[cfg(feature = "delegate-sd-jwt")]
use crate::vc::RequestedPresentation;
use crate::vc::claims::{Claim, Claims, DELEGATIONS_CLAIM, ISSUED_VC_CLAIM};
use crate::vc::core::{HolderBinder, KeyMetadata};
use crate::vc::oid4vp::Error::{Internal, Protocol};
use crate::vc::oid4vp::api::VerifiedPresentationResponse;
#[cfg(feature = "delegate-sd-jwt")]
use crate::vc::oid4vp::api::as_delegate;
#[cfg(feature = "delegate-sd-jwt")]
use crate::vc::oid4vp::delegate::decode_delegate_payload_disclosure;
#[cfg(feature = "delegate-sd-jwt")]
use crate::vc::oid4vp::internal_error::VCSnafu;
use crate::vc::oid4vp::internal_error::{
    AuthorizationResponseDecryptionSnafu, ClaimsSnafu, ClientSnafu, DCQLSnafu,
    DidUrlResolutionSnafu, FormatNotSupportedSnafu, IdTokenValidationSnafu, JsonSnafu, KMSSnafu,
    NonceGenerationSnafu, Oid4VpLibSnafu, ParseSnafu, PresentationExchangeSnafu, X509Snafu,
};
use crate::vc::oid4vp::metadata::{
    SELF_ISSUED_V2, default_client_metadata, default_wallet_metadata, ensure_supported_vp_formats,
};
use crate::vc::oid4vp::protocol_error::ErrorType;
use crate::vc::oid4vp::signer::Signer;
use crate::vc::oid4vp::{
    AuthorizationRequestMetadata, AuthorizationResponse, AuthorizationResponseObject, ClientId,
    ClientIdPrefix, ClientMetadata, CredentialVerificationMetadata, PRESENTATION_SUBMISSION,
    PassAuthRequestObject, PresentationSession, ProtocolError, ResolvedPresentationQuery,
    ResponseMode, ResponseType, STATE, TRANSACTION_DATA_HASHES, TRANSACTION_DATA_HASHES_ALG,
    TransactionDataItem, TransactionDataResponse, get_transaction_data_hash,
};
use crate::vc::presentation_exchange;
use crate::vc::presentation_exchange::{
    PresentationResponse, validate_against_presentation_definition,
};
use crate::vc::{dcql, oid4vp as api};
use one_core_portable::one_crypto::jwe::extract_jwe_header;
#[cfg(feature = "delegate-sd-jwt")]
use openid4vp::core::authorization_request::parameters::DelegateSdJwtTransactionData;
use openid4vp::core::authorization_request::{AuthorizationRequestObject, RequestReference};
use openid4vp::core::object::UntypedObject;
use openid4vp::core::response::parameters::{IdTokenBody as IdToken, TransactionDataHashesAlg};
use ssi::claims::jwt::decode_unverified;
use ssi::dids::DIDURLBuf;
use std::collections::HashMap;
use std::ops::Deref;

pub type Error = api::Error;
pub type Result<T> = core::result::Result<T, Error>;

pub type DecentralizedIdentifierClient<S> =
    openid4vp::verifier::client::DecentralizedIdentifierClient<S>;
pub type RedirectUriClient = openid4vp::verifier::client::RedirectUriClient;

pub use crate::vc::oid4vp::x509::X509Variant;
#[cfg(not(target_arch = "wasm32"))]
pub use crate::vc::oid4vp::x509::{Certificate, X509Client};

const VP_TOKEN: &str = "vp_token";
const ID_TOKEN: &str = "id_token";

#[derive(Debug, Clone)]
pub struct VerifierMetadata {
    pub client_id: ClientId,
    pub key_metadata: KeyMetadata,
    pub client_metadata: ClientMetadata,
    pub x5c_chain: Option<Vec<u8>>,
}

#[derive(Debug, Default, Clone)]
pub(crate) struct PresentationVerificationOptions {
    pub enc_pub_key: Option<JWK>,
    pub audience: Option<String>,
    pub response_uri: Option<String>,
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
            x5c_chain: None,
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

    /// Sets the PEM-encoded, leaf-first X.509 certificate chain carried in the
    /// `x5c` header of the signed Authorization Request Object.
    ///
    /// Used when the Verifier's `client_id` has an X.509 prefix. The leaf must
    /// derive that `client_id` — its SAN DNS name for `x509_san_dns`, its hash
    /// for `x509_hash` — and must certify the Verifier's signing key. Both are
    /// checked when the request is built, where the PEM is parsed.
    pub fn with_x509_certificate_chain(mut self, pem_bytes: Vec<u8>) -> Self {
        self.metadata.x5c_chain = Some(pem_bytes);
        self
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<VF, KH, KMS, NG, HC> api::Verifier for VerifierService<VF, KH, KMS, NG, HC>
where
    VF: vc::core::Verifier,
    KH: KeyHandle + 'static,
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
        let verified = self
            .verify_and_extract_presentation_with_issuer_trust(
                authorization_response,
                session,
                verification_metadata,
            )
            .await?;
        Ok((verified.claims, verified.presentations))
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn verify_and_extract_presentation_with_issuer_trust(
        &self,
        authorization_response: &AuthorizationResponse,
        session: &PresentationSession,
        verification_metadata: &CredentialVerificationMetadata,
    ) -> Result<VerifiedPresentationResponse> {
        let (authorization_response, mut verification_opts) = self
            .resolve_authorization_response(authorization_response)
            .await?;
        self.validate_transaction_data(
            verification_metadata.transaction_data.as_ref(),
            authorization_response.transaction_data_response.as_ref(),
        )?;

        let request_object = session
            .auth_request_jwt
            .as_deref()
            .and_then(Self::request_object_of);
        verification_opts.audience = Self::bound_audience(
            verification_metadata.audience.as_deref(),
            request_object.as_ref(),
        );
        verification_opts.response_uri = request_object
            .as_ref()
            .and_then(|request| request.return_uri())
            .map(|uri| uri.to_string());

        let (vp_token_claims, presentations, issuer_trust) = self
            .do_verify_presentation(
                &session.resolved_presentation_query,
                &session.nonce,
                &authorization_response,
                verification_opts,
                verification_metadata.transaction_data.as_ref(),
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

        Ok(VerifiedPresentationResponse {
            claims,
            presentations,
            issuer_trust,
        })
    }
}

impl<VF, KH, KMS, NG, HC> VerifierService<VF, KH, KMS, NG, HC>
where
    VF: vc::core::Verifier,
    KH: KeyHandle + 'static,
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
                        response_uri: None,
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

    /// A transaction data item is authorized only by one of the credentials it names, and DCQL
    /// `credential_sets` let a wallet leave all of them out.
    fn ensure_transaction_data_bound(
        expected_td: Option<&Vec<TransactionDataItem>>,
        presented_ids: &[&str],
    ) -> Result<()> {
        let unbound = expected_td.into_iter().flatten().any(|item| {
            !item
                .credential_ids
                .iter()
                .any(|id| presented_ids.contains(&id.as_str()))
        });
        if unbound {
            return Err(Protocol {
                source: ProtocolError::new(
                    ErrorType::InvalidTransactionData,
                    Some("Transaction data is not bound to any presented credential".to_string()),
                    None,
                ),
            });
        }

        Ok(())
    }

    #[cfg(feature = "delegate-sd-jwt")]
    async fn verify_presentation_or_delegation(
        &self,
        requested_presentation: &RequestedPresentation,
        holder_binder: Option<HolderBinder>,
        transaction_data: Option<&Vec<TransactionDataItem>>,
        state: &Option<String>,
    ) -> Result<crate::vc::trust::issuer::IssuerTrustVerification> {
        let delegate_items = Self::delegate_items_for(transaction_data, &requested_presentation.id);

        if delegate_items.is_empty() {
            self.verifier
                .verify_presentation_with_issuer_trust(
                    holder_binder,
                    &requested_presentation.presentation,
                    &self.http_client,
                )
                .await
                .context(VCSnafu)
                .map_err(From::from)
        } else {
            let claims = self
                .verifier
                .verify_delegation(
                    holder_binder.clone(),
                    &requested_presentation.presentation,
                    &self.http_client,
                )
                .await
                .context(VCSnafu)?;

            Self::validate_delegate_transaction_data_content(
                delegate_items,
                &requested_presentation.id,
                &claims,
                holder_binder.as_ref(),
                state,
            )?;

            // a delegation grant is signed by the delegating holder's key, not an issuer chain
            Ok(
                crate::vc::trust::issuer::IssuerTrustVerification::without_chain(
                    claims,
                    IssuerTrustOutcome::not_evaluated(
                        crate::vc::trust::issuer::IssuerTrustReason::DidIssuer,
                    ),
                ),
            )
        }
    }

    #[cfg(feature = "delegate-sd-jwt")]
    fn delegate_items_for(
        expected_td: Option<&Vec<TransactionDataItem>>,
        credential_id: &str,
    ) -> Vec<DelegateSdJwtTransactionData> {
        expected_td
            .into_iter()
            .flatten()
            .filter(move |item| item.credential_ids.iter().any(|id| id == credential_id))
            .filter_map(as_delegate)
            .map(ToOwned::to_owned)
            .collect()
    }

    #[cfg(feature = "delegate-sd-jwt")]
    fn validate_delegate_transaction_data_content(
        expected_td: Vec<DelegateSdJwtTransactionData>,
        credential_id: &str,
        claims: &Claims,
        holder_binder: Option<&HolderBinder>,
        state: &Option<String>,
    ) -> Result<()> {
        let last_hop = claims
            .get(DELEGATIONS_CLAIM)
            .and_then(Claim::as_vec)
            .and_then(|hops| hops.last())
            .and_then(Claim::as_vec)
            .ok_or_else(|| Protocol {
                source: ProtocolError::transaction_data(
                    &format!(
                        "delegate transaction data targets credential '{credential_id}', but its presentation is not a delegation chain"
                    ),
                    state.to_owned(),
                ),
            })?;

        let ignored: &[&str] = if holder_binder.is_some() {
            // aud & nonce are validated in dsd_jwt::verify_dsd_jwt
            &["aud", "nonce"]
        } else {
            &[]
        };

        let all_requested_are_disclosed = expected_td.iter().all(|item| {
            decode_delegate_payload_disclosure(item, state)
                .ok()
                .is_some_and(|requested| {
                    let requested = Claim::from(requested);
                    last_hop
                        .iter()
                        .any(|alternative| Self::payloads_match(&requested, alternative, ignored))
                })
        });

        if !all_requested_are_disclosed || last_hop.len() != expected_td.len() {
            return Err(Protocol {
                source: ProtocolError::transaction_data(
                    &format!(
                        "delegate payload(s) disclosed for credential '{credential_id}' do not match what was requested"
                    ),
                    state.to_owned(),
                ),
            });
        }

        Ok(())
    }

    #[cfg(feature = "delegate-sd-jwt")]
    fn payloads_match(requested: &Claim, disclosed: &Claim, ignored: &[&str]) -> bool {
        let (Claim::Object(disclosed), Claim::Object(requested)) = (disclosed, requested) else {
            return false;
        };
        let kept = |map: &HashMap<String, Claim>| -> usize {
            map.keys()
                .filter(|key| !ignored.contains(&key.as_str()))
                .count()
        };

        kept(disclosed) == kept(requested)
            && requested
                .iter()
                .filter(|(key, _)| !ignored.contains(&key.as_str()))
                .all(|(key, value)| disclosed.get(key) == Some(value))
    }

    /// When delegation is verified, claims are returns in the following way:
    /// { "issued_vc": ..., "delegations": [...] }
    /// For DCQL requested claims validation, issued_vc claims should be unwrapped.
    fn get_issued_vc_claims(claim: &Claim) -> Claim {
        match (claim.get(ISSUED_VC_CLAIM), claim.get(DELEGATIONS_CLAIM)) {
            (Some(issued_vc), Some(_)) => issued_vc.clone(),
            _ => claim.clone(),
        }
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
            // The request object is signed, so the Verifier's client-id prefix
            // selects who signs it and how it is authenticated.
            _ => match self.metadata.client_id.get_prefix() {
                ClientIdPrefix::X509SanDns => {
                    self.build_x509_request(
                        X509Variant::SanDns,
                        resolved_presentation_query,
                        nonce,
                        wallet_metadata,
                        auth_request_metadata,
                    )
                    .await
                }
                ClientIdPrefix::X509Hash => {
                    self.build_x509_request(
                        X509Variant::Hash,
                        resolved_presentation_query,
                        nonce,
                        wallet_metadata,
                        auth_request_metadata,
                    )
                    .await
                }
                _ => {
                    self.build_did_request(
                        resolved_presentation_query,
                        nonce,
                        wallet_metadata,
                        auth_request_metadata,
                    )
                    .await
                }
            },
        }
    }

    /// Builds an Authorization Request Object signed with the Verifier's DID
    /// key, authenticated by the `did_url` from its key metadata.
    async fn build_did_request(
        &self,
        resolved_presentation_query: &ResolvedPresentationQuery,
        nonce: Nonce,
        wallet_metadata: &WalletMetadata,
        auth_request_metadata: &AuthorizationRequestMetadata,
    ) -> Result<(Url, Option<String>)> {
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

        let verifier_builder = openid4vp::verifier::Verifier::builder().with_client(did_client);
        self.build_authorization_request_helper(
            resolved_presentation_query,
            nonce,
            wallet_metadata,
            verifier_builder,
            auth_request_metadata,
        )
        .await
    }

    /// Builds an Authorization Request Object for an X.509 `client_id`: signed
    /// with the Verifier's key, with the configured certificate chain in the JWT
    /// `x5c` header. `variant` selects how the `client_id` is derived from the
    /// leaf — its SAN DNS name (`x509_san_dns`) or its hash (`x509_hash`).
    ///
    /// Requires a chain set via [`VerifierService::with_x509_certificate_chain`]
    /// that derives the configured `client_id` and whose leaf public key is the
    /// Verifier's signing key.
    #[cfg(not(target_arch = "wasm32"))]
    async fn build_x509_request(
        &self,
        variant: X509Variant,
        resolved_presentation_query: &ResolvedPresentationQuery,
        nonce: Nonce,
        wallet_metadata: &WalletMetadata,
        auth_request_metadata: &AuthorizationRequestMetadata,
    ) -> Result<(Url, Option<String>)> {
        use openid4vp::verifier::client::Client as _;

        let pem = self.metadata.x5c_chain.as_deref().ok_or_else(|| {
            X509Snafu {
                details: format!(
                    "no certificate chain configured for client_id {}",
                    self.metadata.client_id
                ),
            }
            .build()
        })?;

        let x5c = Certificate::load_pem_chain(pem).map_err(|e| {
            X509Snafu {
                details: format!("cannot parse the configured certificate chain: {e}"),
            }
            .build()
        })?;

        // `X509Client::client_id` reads the leaf directly.
        ensure!(
            !x5c.is_empty(),
            X509Snafu {
                details: format!(
                    "empty certificate chain configured for client_id {}",
                    self.metadata.client_id
                ),
            }
        );

        info!("access to the key {}", self.metadata.key_metadata.kid);
        let verifier_key = self
            .kms
            .get(&self.metadata.key_metadata.kid)
            .await
            .context(KMSSnafu)?;

        // The Wallet checks the request signature against the leaf certificate's
        // public key, so a leaf that does not belong to the signing key produces
        // requests every Wallet rejects. Catch it here instead.
        vc::oid4vp::x509::ensure_leaf_matches_signing_key(&x5c[0], &verifier_key)?;

        let signer: std::sync::Arc<
            dyn openid4vp::signer::Signer<Error = anyhow::Error> + Send + Sync,
        > = std::sync::Arc::new(Signer::new(verifier_key)?);

        let x509_client = X509Client::new(x5c, signer, variant).context(Oid4VpLibSnafu)?;

        // The emitted `client_id` is derived from the leaf certificate, so a
        // mismatch would silently send a different identifier than configured.
        ensure!(
            x509_client.id() == &self.metadata.client_id,
            X509Snafu {
                details: format!(
                    "certificate chain does not match the configured client_id: expected {}, got {}",
                    self.metadata.client_id,
                    x509_client.id()
                ),
            }
        );

        let verifier_builder = openid4vp::verifier::Verifier::builder().with_client(x509_client);
        self.build_authorization_request_helper(
            resolved_presentation_query,
            nonce,
            wallet_metadata,
            verifier_builder,
            auth_request_metadata,
        )
        .await
    }

    /// wasm32 counterpart of [`Self::build_x509_request`]: an X.509 `client_id`
    /// cannot be served on this target.
    #[cfg(target_arch = "wasm32")]
    async fn build_x509_request(
        &self,
        variant: X509Variant,
        _resolved_presentation_query: &ResolvedPresentationQuery,
        _nonce: Nonce,
        _wallet_metadata: &WalletMetadata,
        _auth_request_metadata: &AuthorizationRequestMetadata,
    ) -> Result<(Url, Option<String>)> {
        Err(X509Snafu {
            details: format!(
                "the {} client-id prefix is not supported on wasm32",
                variant.to_prefix()
            ),
        }
        .build()
        .into())
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

        if let Some(verifier_info) = &auth_request_metadata.verifier_info {
            request_builder = request_builder.with_request_parameter(verifier_info.to_owned());
        }

        let client_metadata = match &auth_request_metadata.client_metadata {
            Some(client_metadata) => {
                ensure_supported_vp_formats(client_metadata).map_err(|format| Internal {
                    source: FormatNotSupportedSnafu { format }.build(),
                })?;

                client_metadata.clone()
            }
            None => self.metadata.client_metadata.clone(),
        };

        let mut request_builder = request_builder
            .with_request_parameter(auth_request_metadata.auth_response_options.mode.to_owned())
            .with_request_parameter(NonceSpruce::from(nonce.secret()))
            .with_request_parameter(client_metadata);

        // OID4VP 1.0 §5.8 requires `aud` on a signed Request Object.
        if matches!(auth_req_type, RequestType::SignedJwt(_)) {
            let audience = match wallet_metadata.get::<Issuer>() {
                Some(Ok(Issuer(issuer))) => issuer,
                _ => SELF_ISSUED_V2.to_string(),
            };

            request_builder = request_builder.with_request_parameter(Audience(audience));
        }

        let (auth_request_url, auth_req_jwt) = request_builder
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
        transaction_data: Option<&Vec<TransactionDataItem>>,
    ) -> Result<VerifiedPresentations> {
        let mut result: HashMap<String, Vec<Claim>> = HashMap::new();
        let mut issuer_trust: Vec<IssuerTrust> = vec![];
        let mut validated: HashMap<String, Vec<Claim>> = HashMap::new();
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

        // These checks need only the presented ids, so they run before any presentation is verified.
        if let ResolvedPresentationQuery::DCQL(dcql) = resolved_presentation_query {
            let answered: Vec<&str> = requested_presentations
                .iter()
                .map(|presentation| presentation.id.as_str())
                .collect();
            dcql::ensure_required_queries_answered(dcql, &answered).context(DCQLSnafu)?;
            Self::ensure_transaction_data_bound(transaction_data, &answered)?;
        }

        for requested_presentation in requested_presentations {
            let holder_binder =
                if let Some(false) = requested_presentation.require_cryptographic_holder_binding {
                    None
                } else {
                    Some(HolderBinder {
                        nonce: nonce.to_owned(),
                        verifier_id: presentation_verification_opts
                            .audience
                            .clone()
                            .unwrap_or_else(|| self.metadata.client_id.get_full_id()),
                        response_uri: presentation_verification_opts.response_uri.clone(),
                    })
                };

            let verified: crate::vc::trust::issuer::IssuerTrustVerification;

            #[cfg(feature = "delegate-sd-jwt")]
            {
                verified = self
                    .verify_presentation_or_delegation(
                        &requested_presentation,
                        holder_binder,
                        transaction_data,
                        &authorization_response.state,
                    )
                    .await?;
            }
            #[cfg(not(feature = "delegate-sd-jwt"))]
            {
                verified = self
                    .verifier
                    .verify_presentation_with_issuer_trust(
                        holder_binder,
                        &requested_presentation.presentation,
                        &self.http_client,
                    )
                    .await
                    .context(crate::vc::oid4vp::internal_error::VCSnafu)?;
            }

            let id = requested_presentation.id;
            Self::check_trusted_authorities(
                resolved_presentation_query,
                &id,
                verified.issuer_chain_akis.as_deref(),
            )?;
            let claims = verified.claims;
            issuer_trust.push(IssuerTrust {
                credential_id: id.clone(),
                index: ids.iter().filter(|seen| **seen == id).count(),
                outcome: verified.outcome,
            });
            ids.push(id.clone());
            let claim: Claim = claims.into();
            validated
                .entry(id.clone())
                .or_default()
                .push(Self::get_issued_vc_claims(&claim));
            result.entry(id.clone()).or_default().push(claim);
            presentations
                .entry(id)
                .or_default()
                .push(requested_presentation.presentation);
        }

        Self::validate_against_requested_claims(
            resolved_presentation_query,
            authorization_response,
            &validated,
            ids,
        )?;

        if self.verifier.issuer_trust_mode() == IssuerTrustMode::Enforce
            && issuer_trust
                .iter()
                .any(|entry| entry.outcome.rejected_when_enforced())
        {
            tracing::warn!("presentation rejected: a credential issuer is not trusted");
            return Err(IssuerNotTrustedSnafu { issuer_trust }.build().into());
        }

        let result = HashMap::from_iter(result.into_iter().map(|(k, v)| (k, Claim::Array(v))));
        Ok((Claim::Object(result), presentations, issuer_trust))
    }

    /// Checks a credential against the `aki` trusted authorities of its DCQL query
    /// (OpenID4VP 1.0 §6.1.1.1).
    fn check_trusted_authorities(
        resolved_presentation_query: &ResolvedPresentationQuery,
        credential_id: &str,
        issuer_chain_akis: Option<&[Vec<u8>]>,
    ) -> Result<()> {
        use crate::vc::trust::trusted_authorities::{matches_required_akis, required_akis};

        let ResolvedPresentationQuery::DCQL(dcql) = resolved_presentation_query else {
            return Ok(());
        };
        let Some(required) = dcql
            .credentials()
            .iter()
            .find(|query| query.id().as_str() == credential_id)
            .and_then(required_akis)
        else {
            return Ok(());
        };
        if matches_required_akis(&required, issuer_chain_akis) {
            return Ok(());
        }
        tracing::warn!(
            credential_id,
            "presentation rejected: a credential matches none of the requested trusted authorities"
        );
        Err(
            crate::vc::oid4vp::internal_error::TrustedAuthorityMismatchSnafu {
                credential_id: credential_id.to_string(),
            }
            .build()
            .into(),
        )
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
                dcql::validate_presented_credentials(dcql, credentials).context(DCQLSnafu)?
            }
        };
        Ok(())
    }

    fn request_object_of(request_object_jwt: &str) -> Option<AuthorizationRequestObject> {
        decode_unverified::<UntypedObject>(request_object_jwt)
            .ok()?
            .try_into()
            .ok()
    }

    fn bound_audience(
        audience: Option<&str>,
        request_object: Option<&AuthorizationRequestObject>,
    ) -> Option<String> {
        let dc_api = request_object.is_some_and(|request| {
            matches!(
                request.response_mode(),
                ResponseMode::DcApi | ResponseMode::DcApiJwt
            )
        });

        audience.map(|audience| {
            if dc_api {
                HolderBinder::dc_api_audience(audience)
            } else {
                audience.to_owned()
            }
        })
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
    use crate::vc::formats::mso_mdoc::tests as mdoc;
    use crate::vc::oid4vp::jwe::JweEncryptor;
    use crate::vc::oid4vp::tests::fixtures::multi_presentation::{
        auth_response_options, submission_requirements, transaction_data_items,
    };
    use crate::vc::oid4vp::tests::fixtures::{NONCE, multi_presentation, single_presentation};
    use crate::vc::oid4vp::tests::fixtures::{STATE, VERIFIER_URL};
    use crate::vc::oid4vp::tests::utils::{
        TestVerifierService, VerificationTestCase, build_url, generate_client_metadata,
        self_signed_certificate_pem, unrelated_signing_key, validate_claims, verifier_service,
        verifier_service_with_derived_client_id, verifier_service_with_invalid_kid,
        verifier_service_with_issuer_trust, verifier_service_with_signer_error,
    };
    use crate::vc::oid4vp::verifier::VP_TOKEN;
    use crate::vc::oid4vp::{
        ExpectedOrigins, HashAlgorithm, HttpMethodForAuth, InternalError, TransactionDataHashes,
        TransactionDataItemTypeContent,
    };
    use crate::vc::oid4vp::{PassAuthRequestObject, PresentationSession, ResponseType, Verifier};
    use crate::vc::oid4vp::{VerifierInfo, VerifierInfoEntry};
    use crate::vc::presentation_exchange::PresentationDefinition;
    use base64::Engine;
    use base64::prelude::BASE64_URL_SAFE_NO_PAD;
    use openid4vp::core::authorization_request::parameters::{Audience, VerifierInfoData};
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
                    client_metadata: None,
                    verifier_info: None,
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

    const X509_SAN_DNS_NAME: &str = "verifier.example";
    const X509_SAN_DNS_CLIENT_ID: &str = "x509_san_dns:verifier.example";

    fn x509_client_id(chain: &[Certificate], variant: X509Variant) -> ClientId {
        vc::oid4vp::x509::client_id_from_x509_chain(chain, variant).unwrap()
    }

    /// Wallet metadata that advertises no `x509_*` client-id prefix at all.
    fn wallet_metadata_without_x509() -> WalletMetadata {
        const JSON: &str = r#"{
            "issuer": "https://self-issued.me/v2",
            "authorization_endpoint": "openid4vp://",
            "response_types_supported": ["vp_token", "vp_token id_token"],
            "vp_formats_supported": {
                "dc+sd-jwt": {
                    "sd-jwt_alg_values": ["EdDSA", "ES256"],
                    "kb-jwt_alg_values": ["EdDSA", "ES256"]
                }
            },
            "client_id_prefixes_supported": [
                "decentralized_identifier",
                "redirect_uri"
            ],
            "request_object_signing_alg_values_supported": ["EdDSA", "ES256"],
            "subject_syntax_types_supported": ["did:key"],
            "id_token_types_supported": ["subject_signed_id_token"]
        }"#;

        WalletMetadata::try_from(serde_json::from_str::<UntypedObject>(JSON).unwrap()).unwrap()
    }

    async fn x509_verifier(variant: X509Variant) -> (TestVerifierService, ClientId) {
        let mut derived = None;

        let (verifier, _key) = verifier_service_with_derived_client_id(|key| {
            let pem = self_signed_certificate_pem(key, X509_SAN_DNS_NAME);
            let chain = Certificate::load_pem_chain(pem.as_bytes()).unwrap();
            let client_id = x509_client_id(&chain, variant);
            derived = Some((pem, client_id.clone()));

            client_id
        })
        .await;

        let (pem, client_id) = derived.unwrap();

        (
            verifier.with_x509_certificate_chain(pem.into_bytes()),
            client_id,
        )
    }

    async fn create_x509_request(
        verifier: &TestVerifierService,
        wallet_metadata: Option<&WalletMetadata>,
    ) -> Result<(Url, PresentationSession)> {
        verifier
            .create_authorization_request(
                &single_presentation::sd_jwt::presentation_definition(),
                &AuthorizationRequestMetadata {
                    auth_response_options: auth_response_options(
                        build_url(VERIFIER_URL, "auth"),
                        None,
                    ),
                    transaction_data: None,
                    pass_auth_request_object: PassAuthRequestObject::ByValue,
                    expected_origins: None,
                    client_metadata: None,
                    verifier_info: None,
                },
                wallet_metadata,
            )
            .await
    }

    #[rstest]
    #[case::san_dns(X509Variant::SanDns)]
    #[case::hash(X509Variant::Hash)]
    #[tokio::test]
    async fn generate_x509_auth_request_success(#[case] variant: X509Variant) {
        let (verifier, client_id) = x509_verifier(variant).await;

        // `None` falls back to the SDK default wallet metadata, which is the
        // normal case for cross-device OID4VP — it must advertise the x509
        // prefixes, or an x509 `client_id` would be unusable there.
        let (_url, session) = create_x509_request(&verifier, None).await.unwrap();

        let jwt = session
            .auth_request_jwt
            .expect("an x509 request must be a signed JWT");

        // The request JWT header must carry the certificate chain in `x5c`.
        let header_b64 = jwt.split('.').next().unwrap();
        let header: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(header_b64).unwrap()).unwrap();
        let x5c = header
            .get("x5c")
            .and_then(|v| v.as_array())
            .expect("request JWT header must contain an x5c array");
        assert!(!x5c.is_empty(), "x5c chain must not be empty");

        // The client_id must be the one derived from the leaf certificate.
        let payload_b64 = jwt.split('.').nth(1).unwrap();
        let payload: serde_json::Value =
            serde_json::from_slice(&BASE64_URL_SAFE_NO_PAD.decode(payload_b64).unwrap()).unwrap();
        assert_eq!(
            payload.get("client_id").and_then(|v| v.as_str()),
            Some(client_id.get_full_id().as_str())
        );

        if variant == X509Variant::SanDns {
            assert_eq!(client_id.get_full_id(), X509_SAN_DNS_CLIENT_ID);
        }
    }

    #[tokio::test]
    async fn generate_x509_auth_request_fails_when_wallet_does_not_advertise_prefix() {
        let (verifier, _) = x509_verifier(X509Variant::SanDns).await;

        let result = create_x509_request(&verifier, Some(&wallet_metadata_without_x509())).await;

        assert!(
            result.is_err(),
            "expected rejection when the wallet does not advertise x509_san_dns"
        );
    }

    #[rstest]
    // The leaf certificate's SAN DNS name is `verifier.example`.
    #[case::client_id_mismatch(true, true)]
    #[case::no_certificate_chain(false, false)]
    // A chain deriving the right client_id, but certifying somebody else's key.
    #[case::certificate_does_not_certify_signing_key(true, false)]
    #[tokio::test]
    async fn generate_x509_auth_request_fails_on_certificate_mismatch(
        #[case] with_chain: bool,
        #[case] client_id_mismatch: bool,
    ) {
        let foreign_key = unrelated_signing_key().await;

        let (verifier, _) = verifier_service_with_derived_client_id(|_| {
            ClientId::new(if client_id_mismatch && with_chain {
                "x509_san_dns:other.example".to_string()
            } else {
                X509_SAN_DNS_CLIENT_ID.to_string()
            })
            .unwrap()
        })
        .await;

        let verifier = if with_chain {
            // Minted from `foreign_key`, so it never certifies the verifier's key.
            let pem = self_signed_certificate_pem(&foreign_key, X509_SAN_DNS_NAME);
            verifier.with_x509_certificate_chain(pem.into_bytes())
        } else {
            verifier
        };

        let result = create_x509_request(&verifier, None).await;

        assert!(matches!(
            result,
            Err(Error::Internal {
                source: InternalError::X509 { .. }
            })
        ));
    }

    async fn request_object_for_mode(response_mode: ResponseMode) -> AuthorizationRequestObject {
        let (verifier, _) = verifier_service().await;
        let mut auth_response_options =
            auth_response_options(build_url(VERIFIER_URL, "auth"), None);
        auth_response_options.mode = response_mode;
        let expected_origins = vec![Url::parse("https://example.verifier.org").unwrap().origin()];

        let (_, session) = verifier
            .create_authorization_request(
                &ResolvedPresentationQuery::DCQL(DCQL::new(sample_dcql())),
                &AuthorizationRequestMetadata {
                    transaction_data: None,
                    auth_response_options,
                    pass_auth_request_object: PassAuthRequestObject::ByValue,
                    expected_origins: Some(ExpectedOrigins::new(
                        expected_origins.try_into().unwrap(),
                    )),
                    client_metadata: None,
                    verifier_info: None,
                },
                None,
            )
            .await
            .unwrap();

        TestVerifierService::request_object_of(&session.auth_request_jwt.unwrap()).unwrap()
    }

    #[rstest]
    #[case::plain_dc_api(ResponseMode::DcApi)]
    #[case::encrypted_dc_api_jwt(ResponseMode::DcApiJwt)]
    #[tokio::test]
    async fn bound_audience_prefixes_the_origin_for_a_dc_api_request(
        #[case] response_mode: ResponseMode,
    ) {
        let request = request_object_for_mode(response_mode).await;

        assert_eq!(
            TestVerifierService::bound_audience(
                Some("https://verifier.example.org"),
                Some(&request)
            ),
            Some("origin:https://verifier.example.org".to_string())
        );
        // A caller that already prefixed is not prefixed twice.
        assert_eq!(
            TestVerifierService::bound_audience(
                Some("origin:https://verifier.example.org"),
                Some(&request)
            ),
            Some("origin:https://verifier.example.org".to_string())
        );
    }

    #[rstest]
    #[case::direct_post(ResponseMode::DirectPost)]
    #[case::direct_post_jwt(ResponseMode::DirectPostJwt)]
    #[tokio::test]
    async fn bound_audience_keeps_the_audience_verbatim_for_a_non_dc_api_request(
        #[case] response_mode: ResponseMode,
    ) {
        let request = request_object_for_mode(response_mode).await;

        assert_eq!(
            TestVerifierService::bound_audience(Some("x509_hash:abc"), Some(&request)),
            Some("x509_hash:abc".to_string())
        );
    }

    #[test]
    fn bound_audience_keeps_the_audience_verbatim_without_a_request_object() {
        assert_eq!(
            TestVerifierService::bound_audience(Some("https://verifier.example.org"), None),
            Some("https://verifier.example.org".to_string())
        );
        assert_eq!(TestVerifierService::bound_audience(None, None), None);
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
                    client_metadata: None,
                    verifier_info: None,
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
    async fn generate_signed_auth_request_carries_verifier_info() {
        let request_uri = build_url(VERIFIER_URL, "request");
        let (verifier, _did) = verifier_service().await;
        let auth_response_options = auth_response_options(build_url(VERIFIER_URL, "auth"), None);

        let rprc = test_fixtures::jws(
            &json!({ "alg": "ES256" }),
            &json!({ "iss": "registrar" }),
            &test_fixtures::keys().verifier,
        );
        let entries = NonEmptyVec::new(VerifierInfoEntry {
            format: "urn:etsi:119472-2:rc".to_string(),
            data: VerifierInfoData::String(rprc.clone()),
            credential_ids: None,
        });

        let (_url, session) = verifier
            .create_authorization_request(
                &ResolvedPresentationQuery::DCQL(DCQL::new(sample_dcql())),
                &AuthorizationRequestMetadata {
                    transaction_data: None,
                    auth_response_options,
                    pass_auth_request_object: PassAuthRequestObject::ByReference {
                        uri: request_uri,
                        method: Some(HttpMethodForAuth::POST),
                    },
                    expected_origins: None,
                    client_metadata: None,
                    verifier_info: Some(entries.into()),
                },
                None,
            )
            .await
            .unwrap();

        let request =
            decode_unverified::<UntypedObject>(session.auth_request_jwt.unwrap().as_str()).unwrap();
        let claim = request
            .get::<VerifierInfo>()
            .expect("verifier_info is absent from the request object")
            .unwrap();

        assert_eq!(claim.0.len(), 1);
        assert_eq!(claim.0[0].format, "urn:etsi:119472-2:rc");
        assert_eq!(claim.0[0].data, VerifierInfoData::String(rprc));
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
                    client_metadata: None,
                    verifier_info: None,
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
                    client_metadata: None,
                    verifier_info: None,
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
                    client_metadata: None,
                    verifier_info: None,
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
                    client_metadata: None,
                    verifier_info: None,
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
                    client_metadata: None,
                    verifier_info: None,
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
                    client_metadata: None,
                    verifier_info: None,
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
                    client_metadata: None,
                    verifier_info: None,
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

    fn mdoc_session() -> PresentationSession {
        PresentationSession {
            nonce: Nonce::from_secret(mdoc::NONCE.to_string()),
            resolved_presentation_query: ResolvedPresentationQuery::DCQL(
                sample_dcql_query_for_mso_mdoc_vp_request(),
            ),
            auth_request_jwt: Default::default(),
        }
    }

    fn mdoc_response(vp: String) -> AuthorizationResponse {
        let mut vp_token = HashMap::new();
        vp_token.insert("mDL", Value::Array(vec![Value::String(vp)]));
        AuthorizationResponse::Plain(AuthorizationResponseObject {
            vp_token: serde_json::to_value(vp_token).unwrap(),
            presentation_submission: None,
            id_token: None,
            state: None,
            transaction_data_response: None,
        })
    }

    async fn verify_mdoc_with_trust(
        vp: String,
        config: crate::vc::trust::issuer::IssuerTrustConfig,
    ) -> Result<crate::vc::oid4vp::VerifiedPresentationResponse> {
        verifier_service_with_issuer_trust(config)
            .await
            .verify_and_extract_presentation_with_issuer_trust(
                &mdoc_response(vp),
                &mdoc_session(),
                &CredentialVerificationMetadata {
                    transaction_data: None,
                    audience: Some(mdoc::VERIFIER.to_string()),
                },
            )
            .await
    }

    fn trust(
        mode: IssuerTrustMode,
        anchors: Vec<crate::vc::trust::issuer::TrustAnchor>,
    ) -> crate::vc::trust::issuer::IssuerTrustConfig {
        crate::vc::trust::issuer::IssuerTrustConfig {
            mode,
            anchors,
            ..Default::default()
        }
    }

    fn iaca_anchor(pem: String) -> crate::vc::trust::issuer::TrustAnchor {
        crate::vc::trust::issuer::TrustAnchor {
            pem,
            source_ref: Some("trust_list:iaca".to_string()),
            // an mDL is an EAA
            role: Some("eaa_provider".to_string()),
            service_type: None,
        }
    }

    #[tokio::test]
    async fn verifier_validating_mso_mdoc_vp_works_correctly() {
        let (vp, iaca) = mdoc::sample_mso_mdoc_vp_with_iaca();

        let verified =
            verify_mdoc_with_trust(vp, trust(IssuerTrustMode::Enforce, vec![iaca_anchor(iaca)]))
                .await
                .unwrap();

        let claims = &verified.claims["vp_token"]["mDL"].as_vec().unwrap()[0]["org.iso.18013.5.1"];
        assert_eq!(claims["family_name"].as_str(), Some("Mustermann"));
        assert_eq!(claims["given_name"].as_str(), Some("Erika"));
        assert_eq!(verified.issuer_trust.len(), 1);
        let entry = &verified.issuer_trust[0];
        assert_eq!((entry.credential_id.as_str(), entry.index), ("mDL", 0));
        assert_eq!(
            entry.outcome.status,
            crate::vc::trust::issuer::IssuerTrustStatus::Trusted
        );
        assert_eq!(entry.outcome.source_ref.as_deref(), Some("trust_list:iaca"));
    }

    #[tokio::test]
    async fn mso_mdoc_without_anchors_is_rejected_under_enforce() {
        let error = verifier_service()
            .await
            .0
            .verify_presentation(
                &mdoc_response(mdoc::sample_mso_mdoc_vp()),
                &mdoc_session(),
                &CredentialVerificationMetadata {
                    transaction_data: None,
                    audience: Some(mdoc::VERIFIER.to_string()),
                },
            )
            .await
            .unwrap_err();

        let crate::vc::oid4vp::Error::Internal {
            source: InternalError::IssuerNotTrusted { issuer_trust },
        } = error
        else {
            panic!("expected issuer_not_trusted, got {error}");
        };
        assert_eq!(
            issuer_trust[0].outcome.reason,
            Some(crate::vc::trust::issuer::IssuerTrustReason::NoAnchorsConfigured)
        );
    }

    #[tokio::test]
    async fn mso_mdoc_without_anchors_is_reported_under_report() {
        let verified = verify_mdoc_with_trust(
            mdoc::sample_mso_mdoc_vp(),
            trust(IssuerTrustMode::Report, vec![]),
        )
        .await
        .unwrap();

        assert_eq!(
            verified.issuer_trust[0].outcome.status,
            crate::vc::trust::issuer::IssuerTrustStatus::NotEvaluated
        );
    }

    #[tokio::test]
    async fn mso_mdoc_under_an_unrelated_iaca_is_rejected_under_enforce_and_reported_under_report()
    {
        let (_, unrelated_iaca) = mdoc::sample_mso_mdoc_vp_with_iaca();
        let (vp, _) = mdoc::sample_mso_mdoc_vp_with_iaca();

        let enforced = verify_mdoc_with_trust(
            vp.clone(),
            trust(
                IssuerTrustMode::Enforce,
                vec![iaca_anchor(unrelated_iaca.clone())],
            ),
        )
        .await;
        assert!(
            matches!(
                enforced,
                Err(crate::vc::oid4vp::Error::Internal {
                    source: InternalError::IssuerNotTrusted { .. }
                })
            ),
            "{enforced:?}"
        );

        let reported = verify_mdoc_with_trust(
            vp,
            trust(IssuerTrustMode::Report, vec![iaca_anchor(unrelated_iaca)]),
        )
        .await
        .unwrap();
        assert_eq!(
            reported.issuer_trust[0].outcome.reason,
            Some(crate::vc::trust::issuer::IssuerTrustReason::NoAnchorMatch)
        );
    }

    /// Two mDLs, only `pid` under the anchor; the untrusted one comes first, so every entry must be
    /// evaluated.
    async fn verify_two_mdls(
        mode: IssuerTrustMode,
    ) -> Result<crate::vc::oid4vp::VerifiedPresentationResponse> {
        let (pid, iaca) = mdoc::sample_mso_mdoc_vp_with_iaca();
        let (diploma, _) = mdoc::sample_mso_mdoc_vp_with_iaca();
        let query = |id: &str| {
            json!({
                "id": id,
                "format": "mso_mdoc",
                "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
                "claims": [{ "path": ["org.iso.18013.5.1", "family_name"] }],
            })
        };
        let dcql: DCQL =
            serde_json::from_value(json!({ "credentials": [query("diploma"), query("pid")] }))
                .unwrap();
        let session = PresentationSession {
            resolved_presentation_query: ResolvedPresentationQuery::DCQL(dcql),
            ..mdoc_session()
        };
        let response = AuthorizationResponse::Plain(AuthorizationResponseObject {
            vp_token: json!({ "pid": [pid], "diploma": [diploma] }),
            presentation_submission: None,
            id_token: None,
            state: None,
            transaction_data_response: None,
        });

        verifier_service_with_issuer_trust(trust(mode, vec![iaca_anchor(iaca)]))
            .await
            .verify_and_extract_presentation_with_issuer_trust(
                &response,
                &session,
                &CredentialVerificationMetadata {
                    transaction_data: None,
                    audience: Some(mdoc::VERIFIER.to_string()),
                },
            )
            .await
    }

    fn trust_by_query(
        entries: &[crate::vc::trust::issuer::IssuerTrust],
    ) -> Vec<(String, usize, crate::vc::trust::issuer::IssuerTrustStatus)> {
        let mut entries: Vec<_> = entries
            .iter()
            .map(|entry| {
                (
                    entry.credential_id.clone(),
                    entry.index,
                    entry.outcome.status,
                )
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        entries
    }

    #[tokio::test]
    async fn mixed_presentation_is_reported_entry_by_entry_under_report() {
        use crate::vc::trust::issuer::IssuerTrustStatus::{Trusted, Untrusted};

        let verified = verify_two_mdls(IssuerTrustMode::Report).await.unwrap();

        assert_eq!(
            trust_by_query(&verified.issuer_trust),
            [
                ("diploma".to_string(), 0, Untrusted),
                ("pid".to_string(), 0, Trusted)
            ]
        );
    }

    #[tokio::test]
    async fn mixed_presentation_fails_under_enforce_with_every_entry() {
        use crate::vc::trust::issuer::IssuerTrustStatus::{Trusted, Untrusted};

        let error = verify_two_mdls(IssuerTrustMode::Enforce).await.unwrap_err();

        let crate::vc::oid4vp::Error::Internal {
            source: InternalError::IssuerNotTrusted { issuer_trust },
        } = error
        else {
            panic!("expected issuer_not_trusted, got {error}");
        };
        assert_eq!(
            trust_by_query(&issuer_trust),
            [
                ("diploma".to_string(), 0, Untrusted),
                ("pid".to_string(), 0, Trusted)
            ]
        );
    }

    /// An mDL under a fresh IACA, verified against a query whose `trusted_authorities` hold the
    /// `aki` of that IACA and of an unrelated one.
    async fn verify_mdl_requesting(
        mode: IssuerTrustMode,
        anchors: impl FnOnce(&str, &str) -> Vec<crate::vc::trust::issuer::TrustAnchor>,
        trusted_authorities: impl FnOnce(&str, &str) -> Value,
    ) -> Result<crate::vc::oid4vp::VerifiedPresentationResponse> {
        use crate::vc::trust::trusted_authorities::derive_trusted_authority_akis;

        let (vp, iaca) = mdoc::sample_mso_mdoc_vp_with_iaca();
        let (_, unrelated) = mdoc::sample_mso_mdoc_vp_with_iaca();
        let aki = |pem: &str| {
            derive_trusted_authority_akis(&[iaca_anchor(pem.to_string())]).values[0]
                .as_base64url()
                .to_string()
        };
        let dcql: DCQL = serde_json::from_value(json!({ "credentials": [{
            "id": "mDL",
            "format": "mso_mdoc",
            "meta": { "doctype_value": "org.iso.18013.5.1.mDL" },
            "claims": [{ "path": ["org.iso.18013.5.1", "family_name"] }],
            "trusted_authorities": trusted_authorities(&aki(&iaca), &aki(&unrelated)),
        }] }))
        .unwrap();
        let session = PresentationSession {
            resolved_presentation_query: ResolvedPresentationQuery::DCQL(dcql),
            ..mdoc_session()
        };

        verifier_service_with_issuer_trust(trust(mode, anchors(&iaca, &unrelated)))
            .await
            .verify_and_extract_presentation_with_issuer_trust(
                &mdoc_response(vp),
                &session,
                &CredentialVerificationMetadata {
                    transaction_data: None,
                    audience: Some(mdoc::VERIFIER.to_string()),
                },
            )
            .await
    }

    fn is_trusted_authority_mismatch(
        result: &Result<crate::vc::oid4vp::VerifiedPresentationResponse>,
    ) -> bool {
        matches!(
            result,
            Err(crate::vc::oid4vp::Error::Internal {
                source: InternalError::TrustedAuthorityMismatch { credential_id },
            }) if credential_id == "mDL"
        )
    }

    #[tokio::test]
    async fn mso_mdoc_under_the_requested_authority_is_verified() {
        let verified = verify_mdl_requesting(
            IssuerTrustMode::Enforce,
            |iaca, _| vec![iaca_anchor(iaca.to_string())],
            |requested, _| json!([{ "type": "aki", "values": [requested] }]),
        )
        .await
        .unwrap();

        assert_eq!(
            verified.issuer_trust[0].outcome.status,
            crate::vc::trust::issuer::IssuerTrustStatus::Trusted
        );
    }

    #[tokio::test]
    async fn mso_mdoc_outside_the_requested_authorities_fails_in_both_modes() {
        for mode in [IssuerTrustMode::Enforce, IssuerTrustMode::Report] {
            let result = verify_mdl_requesting(
                mode,
                |iaca, _| vec![iaca_anchor(iaca.to_string())],
                |_, unrelated| json!([{ "type": "aki", "values": [unrelated] }]),
            )
            .await;

            assert!(
                is_trusted_authority_mismatch(&result),
                "{mode:?}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn only_aki_queries_are_checked_against_the_presented_chain() {
        let etsi_tl = json!({ "type": "etsi_tl", "values": ["https://tl.example.com/tl.xml"] });

        let etsi_tl_only = verify_mdl_requesting(
            IssuerTrustMode::Report,
            |iaca, _| vec![iaca_anchor(iaca.to_string())],
            |_, _| json!([etsi_tl.clone()]),
        )
        .await;
        // an aki miss may be satisfied by the etsi_tl entry, which is not evaluated
        let aki_miss_with_etsi_tl = verify_mdl_requesting(
            IssuerTrustMode::Report,
            |iaca, _| vec![iaca_anchor(iaca.to_string())],
            |_, unrelated| json!([{ "type": "aki", "values": [unrelated] }, etsi_tl.clone()]),
        )
        .await;

        assert!(etsi_tl_only.is_ok(), "{etsi_tl_only:?}");
        assert!(aki_miss_with_etsi_tl.is_ok(), "{aki_miss_with_etsi_tl:?}");
    }

    #[tokio::test]
    async fn a_requested_authority_does_not_make_the_issuer_trusted() {
        let verified = verify_mdl_requesting(
            IssuerTrustMode::Report,
            |_, unrelated| vec![iaca_anchor(unrelated.to_string())],
            |requested, _| json!([{ "type": "aki", "values": [requested] }]),
        )
        .await
        .unwrap();

        assert_eq!(
            verified.issuer_trust[0].outcome.reason,
            Some(crate::vc::trust::issuer::IssuerTrustReason::NoAnchorMatch)
        );
    }

    #[tokio::test]
    async fn an_untrusted_issuer_outside_the_requested_authorities_is_a_mismatch_under_enforce() {
        // the query criterion is checked per credential, before the enforce decision
        let result = verify_mdl_requesting(
            IssuerTrustMode::Enforce,
            |_, unrelated| vec![iaca_anchor(unrelated.to_string())],
            |_, unrelated| json!([{ "type": "aki", "values": [unrelated] }]),
        )
        .await;

        assert!(is_trusted_authority_mismatch(&result), "{result:?}");
    }

    #[test]
    fn an_issuer_without_a_certificate_chain_misses_an_aki_query() {
        let dcql: DCQL = serde_json::from_value(json!({ "credentials": [{
            "id": "pid",
            "format": "dc+sd-jwt",
            "meta": { "vct_values": ["urn:eudi:pid:1"] },
            "trusted_authorities": [{ "type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"] }],
        }] }))
        .unwrap();
        let query = ResolvedPresentationQuery::DCQL(dcql);

        // a DID issuer has no chain
        let error = TestVerifierService::check_trusted_authorities(&query, "pid", None)
            .expect_err("a DID issuer must miss an aki query");

        assert!(
            matches!(
                &error,
                crate::vc::oid4vp::Error::Internal {
                    source: InternalError::TrustedAuthorityMismatch { credential_id },
                } if credential_id == "pid"
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn trusted_authorities_reach_the_signed_request_and_the_session() {
        let (verifier, _) = verifier_service().await;
        let trusted_authorities = json!([
            { "type": "aki", "values": ["s9tIpPmhxdiuNkHMEWNpYim8S8Y"] },
            { "type": "etsi_tl", "values": ["https://tl.example.com/tl.xml"] },
            { "type": "x_custom", "values": ["anything"] }
        ]);
        let mut query = serde_json::to_value(sample_dcql_query_for_mso_mdoc_vp_request()).unwrap();
        query["credentials"][0]["trusted_authorities"] = trusted_authorities.clone();
        let dcql: DCQL = serde_json::from_value(query).unwrap();

        let (_, session) = verifier
            .create_authorization_request(
                &ResolvedPresentationQuery::DCQL(dcql),
                &AuthorizationRequestMetadata {
                    transaction_data: None,
                    auth_response_options: auth_response_options(
                        build_url(VERIFIER_URL, "auth"),
                        None,
                    ),
                    pass_auth_request_object: PassAuthRequestObject::ByValue,
                    expected_origins: None,
                    client_metadata: None,
                    verifier_info: None,
                },
                None,
            )
            .await
            .unwrap();

        let request = serde_json::to_value(
            decode_unverified::<UntypedObject>(session.auth_request_jwt.as_deref().unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            request["dcql_query"]["credentials"][0]["trusted_authorities"],
            trusted_authorities
        );
        let stored = serde_json::to_value(&session.resolved_presentation_query).unwrap();
        assert_eq!(
            stored["dcql_query"]["credentials"][0]["trusted_authorities"],
            trusted_authorities
        );
    }

    #[tokio::test]
    async fn mso_mdoc_bound_to_another_nonce_still_fails_under_report() {
        let (vp, iaca) = mdoc::sample_mso_mdoc_vp_with_iaca();
        // report mode relaxes only the anchor decision, never the device binding
        let session = PresentationSession {
            nonce: Nonce::from_secret("another-nonce".to_string()),
            ..mdoc_session()
        };

        let result = verifier_service_with_issuer_trust(trust(
            IssuerTrustMode::Report,
            vec![iaca_anchor(iaca)],
        ))
        .await
        .verify_and_extract_presentation_with_issuer_trust(
            &mdoc_response(vp),
            &session,
            &CredentialVerificationMetadata {
                transaction_data: None,
                audience: Some(mdoc::VERIFIER.to_string()),
            },
        )
        .await;

        assert!(
            !matches!(
                result,
                Ok(_)
                    | Err(crate::vc::oid4vp::Error::Internal {
                        source: InternalError::IssuerNotTrusted { .. }
                    })
            ),
            "{result:?}"
        );
    }

    #[rstest]
    #[case::one_option_answered(json!([{"options": [["pid_sdjwt"], ["mDL"]]}]), None)]
    #[case::required_set_unanswered(
        json!([{"options": [["pid_sdjwt"]]}, {"required": false, "options": [["mDL"]]}]),
        Some("Credential sets validation error")
    )]
    #[case::no_credential_sets(
        Value::Null,
        Some("Credential(s) for credential-query with id = pid_sdjwt not found")
    )]
    #[tokio::test]
    async fn verify_mso_mdoc_vp_answering_one_of_two_credential_queries(
        #[case] credential_sets: Value,
        #[case] expected_error: Option<&str>,
    ) {
        let (verifier, response) = anchored_mso_mdoc_response(None).await;

        let result = verifier
            .verify_presentation(
                &AuthorizationResponse::Plain(response),
                &pid_sd_jwt_or_mdl_session(credential_sets),
                &CredentialVerificationMetadata {
                    transaction_data: None,
                    audience: Some(mdoc::VERIFIER.to_string()),
                },
            )
            .await;

        match expected_error {
            None => {
                let claims = result.unwrap();
                let mdl = &claims["vp_token"]["mDL"].as_vec().unwrap()[0]["org.iso.18013.5.1"];
                assert_eq!(mdl["given_name"].as_str(), Some("Erika"));
                assert!(claims["vp_token"].get("pid_sdjwt").is_none());
            }
            Some(expected) => {
                let err = result.unwrap_err().to_string();
                assert!(err.contains(expected), "{err}");
            }
        }
    }

    #[rstest]
    #[case::bound_to_presented_credential(
        "mDL",
        json!([{"options": [["pid_sdjwt"], ["mDL"]]}]),
        None
    )]
    #[case::bound_to_omitted_credential(
        "pid_sdjwt",
        json!([{"options": [["pid_sdjwt"], ["mDL"]]}]),
        Some("Transaction data is not bound to any presented credential")
    )]
    #[case::bound_to_missing_required_credential(
        "pid_sdjwt",
        Value::Null,
        Some("Credential(s) for credential-query with id = pid_sdjwt not found")
    )]
    #[tokio::test]
    async fn verify_mso_mdoc_vp_requires_transaction_data_bound_to_presented_credential(
        #[case] credential_id: &str,
        #[case] credential_sets: Value,
        #[case] expected_error: Option<&str>,
    ) {
        let item = TransactionDataItem {
            credential_ids: vec![credential_id.to_string()],
            transaction_data_hashes_alg: None,
            content: TransactionDataItemTypeContent::Unknown {
                type_: "some_type".to_string(),
                data: Map::new(),
            },
        };
        let hashes = TransactionDataResponse {
            transaction_data_hashes: TransactionDataHashes(vec![
                get_transaction_data_hash(&item, HashAlgorithm::Sha256).unwrap(),
            ]),
            transaction_data_hashes_alg: None,
        };
        let (verifier, response) = anchored_mso_mdoc_response(Some(hashes)).await;

        let result = verifier
            .verify_presentation(
                &AuthorizationResponse::Plain(response),
                &pid_sd_jwt_or_mdl_session(credential_sets),
                &CredentialVerificationMetadata {
                    transaction_data: Some(vec![item]),
                    audience: Some(mdoc::VERIFIER.to_string()),
                },
            )
            .await;

        match expected_error {
            None => assert!(result.is_ok(), "{:?}", result.err()),
            Some(expected) => {
                let err = result.unwrap_err().to_string();
                assert!(err.contains(expected), "{err}");
            }
        }
    }

    #[tokio::test]
    async fn verify_presentation_rejects_unanswered_query_before_verifying_presentations() {
        let (verifier, _) = verifier_service().await;
        let mut response = mso_mdoc_response(mdoc::sample_mso_mdoc_vp(), None);
        response.vp_token = json!({ "mDL": ["not a device response"] });

        let err = verifier
            .verify_presentation(
                &AuthorizationResponse::Plain(response),
                &pid_sd_jwt_or_mdl_session(Value::Null),
                &CredentialVerificationMetadata {
                    transaction_data: None,
                    audience: Some(mdoc::VERIFIER.to_string()),
                },
            )
            .await
            .unwrap_err()
            .to_string();

        assert!(
            err.contains("Credential(s) for credential-query with id = pid_sdjwt not found"),
            "{err}"
        );
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

    #[rstest]
    #[should_panic(expected = "Error while getting the jwe header")]
    #[case("not_even_jwt".to_string())]
    #[should_panic(expected = "Error while getting the key handle for ac")]
    #[case(jwe())]
    #[tokio::test]
    async fn resolve_authorization_response_jwe_negative(#[case] jwt: String) {
        let (verifier, _) = verifier_service().await;

        let result = verifier
            .resolve_authorization_response(&AuthorizationResponse::Jwe(jwt))
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

    #[tokio::test]
    async fn signed_auth_request_carries_static_discovery_audience() {
        let request = signed_request_object(None).await;

        assert_eq!(audience_of(&request), SELF_ISSUED_V2);
    }

    #[tokio::test]
    async fn signed_auth_request_carries_discovered_wallet_audience() {
        let metadata = wallet_metadata_with_issuer("https://wallet.example.org");
        let request = signed_request_object(Some(&metadata)).await;

        assert_eq!(audience_of(&request), "https://wallet.example.org");
    }

    /// Encrypted authorization response for a recipient key the verifier does not hold
    /// (`kid: ac`), carrying a key-bound SD-JWT presentation.
    fn jwe() -> String {
        let keys = test_fixtures::keys();
        let sd_jwt = test_fixtures::sd_jwt(
            &json!({
                "typ": "dc+sd-jwt",
                "alg": "ES256",
                "kid": test_fixtures::did_key_url(&keys.issuer)
            }),
            &json!({
                "iat": 1756132278,
                "sub": test_fixtures::did_key(&keys.holder),
                "vct": "https://credentials.example.com/identity_credential",
                "_sd_alg": "sha-256",
                "iss": test_fixtures::did_key(&keys.issuer),
                "exp": 1787668278,
                "nbf": 1756132278,
                "cnf": {
                    "jwk": keys.holder.to_public()
                }
            }),
            &[r#"["kH5kXGmYa82ylXaOfFP_zA", "name", "Mark"]"#],
            &keys.issuer,
        );
        let vp_token = test_fixtures::sd_jwt_kb(
            &sd_jwt,
            &json!({
                "typ": "kb+jwt",
                "alg": "ES256"
            }),
            &json!({
                "aud": test_fixtures::did_key(&keys.verifier),
                "iat": 1756132278,
                "nonce": "3DaLwdi89qDgplpSwAspX6wWzm6pLkzaN3Xuk-ar5zY"
            }),
            &keys.holder,
        );
        let response = json!({
            "vp_token": vp_token,
            "presentation_submission": {
                "id": "d5dec2be-1f86-4ba5-b021-9b18aa769afa",
                "definition_id": "327ad171-c80a-485b-b098-50d7ad278ef6",
                "descriptor_map": [{
                    "id": "Identity-1",
                    "format": "dc+sd-jwt",
                    "path": "$",
                    "path_nested": null
                }]
            }
        });
        test_fixtures::jwe(
            &json!({
                "kid": "ac",
                "enc": "A128CBC-HS256",
                "alg": "ECDH-ES",
                "apu": "some_nonce",
                "apv": "some_nonce"
            }),
            &serde_json::to_vec(&response).unwrap(),
            &keys.verifier,
        )
    }

    fn wallet_metadata_with_issuer(issuer: &str) -> WalletMetadata {
        let mut metadata = wallet_metadata_without_x509();
        metadata.insert(Issuer(issuer.to_string()));

        metadata
    }

    async fn signed_request_object(wallet_metadata: Option<&WalletMetadata>) -> UntypedObject {
        let request_uri = build_url(VERIFIER_URL, "request");
        let (verifier, _did) = verifier_service().await;
        let auth_response_options = auth_response_options(build_url(VERIFIER_URL, "auth"), None);

        let (_url, session) = verifier
            .create_authorization_request(
                &ResolvedPresentationQuery::DCQL(DCQL::new(sample_dcql())),
                &AuthorizationRequestMetadata {
                    transaction_data: None,
                    auth_response_options,
                    pass_auth_request_object: PassAuthRequestObject::ByReference {
                        uri: request_uri,
                        method: Some(HttpMethodForAuth::POST),
                    },
                    expected_origins: None,
                    client_metadata: None,
                    verifier_info: None,
                },
                wallet_metadata,
            )
            .await
            .unwrap();

        decode_unverified::<UntypedObject>(session.auth_request_jwt.unwrap().as_str()).unwrap()
    }

    fn audience_of(request: &UntypedObject) -> String {
        request
            .get::<Audience>()
            .expect("aud is absent from the signed request object")
            .unwrap()
            .0
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

    /// A `pid_sdjwt` (dc+sd-jwt) query next to the `mDL` query of the mdoc fixture.
    fn pid_sd_jwt_or_mdl_session(credential_sets: Value) -> PresentationSession {
        let mut dcql = serde_json::to_value(sample_dcql_query_for_mso_mdoc_vp_request()).unwrap();
        dcql["credentials"].as_array_mut().unwrap().insert(
            0,
            json!({"id": "pid_sdjwt", "format": "dc+sd-jwt", "meta": {"vct_values": ["urn:eudi:pid:1"]}}),
        );
        dcql["credential_sets"] = credential_sets;
        PresentationSession {
            nonce: Nonce::from_secret(mdoc::NONCE.to_string()),
            resolved_presentation_query: ResolvedPresentationQuery::DCQL(
                serde_json::from_value(dcql).unwrap(),
            ),
            auth_request_jwt: Default::default(),
        }
    }

    /// The mdoc fixture presented for the `mDL` query only.
    /// A verifier enforcing issuer trust, anchored on the IACA of the mDL in the response.
    async fn anchored_mso_mdoc_response(
        transaction_data_response: Option<TransactionDataResponse>,
    ) -> (TestVerifierService, AuthorizationResponseObject) {
        let (vp, iaca) = mdoc::sample_mso_mdoc_vp_with_iaca();
        let verifier = verifier_service_with_issuer_trust(trust(
            IssuerTrustMode::Enforce,
            vec![iaca_anchor(iaca)],
        ))
        .await;
        (verifier, mso_mdoc_response(vp, transaction_data_response))
    }

    fn mso_mdoc_response(
        vp: String,
        transaction_data_response: Option<TransactionDataResponse>,
    ) -> AuthorizationResponseObject {
        AuthorizationResponseObject {
            vp_token: json!({ "mDL": [vp] }),
            presentation_submission: None,
            id_token: None,
            state: None,
            transaction_data_response,
        }
    }
}
