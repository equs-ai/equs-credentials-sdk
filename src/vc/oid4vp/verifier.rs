use async_trait::async_trait;
use openid4vp::core::authorization_request::parameters::{
    ClientId, IdTokenType, Nonce as NonceSpruce, Scope, State,
};
use openid4vp::core::metadata::WalletMetadata;
use openid4vp::verifier::by_reference::ByReference;
use openid4vp::verifier::request_builder::RequestType;
use serde_json::{Value as Json, Value};
use snafu::{ResultExt, ensure};
use std::fmt::Debug;
use std::marker::PhantomData;
use tracing::{Level, info, instrument};
use url::Url;

use crate::did::JWKResolver;
use crate::did::universal::UniversalResolver;
use crate::http::HttpClient;
use crate::kms::{KeyHandle, Kms};
use crate::nonce::{Nonce, NonceHandler};
use crate::utils::wasm::{WasmNotSend, WasmNotSync};
use crate::vc;
use crate::vc::claims::{Claim, Claims};
use crate::vc::core::KeyMetadata;
use crate::vc::oid4vp::Error::{Internal, Protocol};
use crate::vc::oid4vp::internal_error::{
    AuthorizationResponseDecryptionSnafu, ClaimsSnafu, ClientIdSnafu, DCQLSnafu,
    DidUrlResolutionSnafu, IdTokenValidationSnafu, JsonSnafu, KMSSnafu, NonceGenerationSnafu,
    Oid4VpLibSnafu, ParseSnafu, PresentationExchangeSnafu, VCSnafu,
};
use crate::vc::oid4vp::jwe_utils::{add_public_private_keys, get_private_key_handler};
use crate::vc::oid4vp::metadata::{default_client_metadata, default_wallet_metadata};
use crate::vc::oid4vp::signer::Signer;
use crate::vc::oid4vp::{
    AuthResponseOptions, AuthorizationResponse, AuthorizationResponseObject, ClientMetadata,
    PassAuthRequestObject, PresentationSession, ProtocolError, ResolvedPresentationQuery,
    ResponseMode, ResponseType,
};
use crate::vc::presentation_exchange;
use crate::vc::presentation_exchange::{
    PresentationResponse, validate_against_presentation_definition,
};
use crate::vc::{dcql, oid4vp as api};
use one_crypto::jwe::{decrypt_jwe_payload, extract_jwe_header};
use openid4vp::core::authorization_request::RequestReference;
use openid4vp::core::response::parameters::IdTokenBody as IdToken;
use ssi::dids::DIDURLBuf;
use std::collections::HashMap;
use std::ops::Deref;

pub type Error = api::Error;
pub type Result<T> = core::result::Result<T, Error>;

pub type DIDClient<S> = openid4vp::verifier::client::DIDClient<S>;
pub type X509SanClient = openid4vp::verifier::client::X509SanClient;
pub type RedirectUriClient = openid4vp::verifier::client::RedirectUriClient;
const VP_TOKEN: &str = "vp_token";
const ID_TOKEN: &str = "id_token";

#[derive(Debug, Clone)]
pub struct VerifierMetadata {
    pub client_id: String,
    pub key_metadata: KeyMetadata,
    pub client_metadata: ClientMetadata,
}

pub struct VerifierService<VF, KH, KMS, NG, HC>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH>,
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
    KMS: Kms<KH>,
    NG: NonceHandler,
    HC: HttpClient,
{
    #[allow(clippy::too_many_arguments)]
    #[instrument(level = Level::TRACE, skip(verifier, kms, nonce_generator, http_client, did_resolver))]
    pub fn new(
        verifier: VF,
        kms: KMS,
        nonce_generator: NG,
        http_client: HC,
        client_id: String,
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
    KMS: Kms<KH>,
    NG: NonceHandler,
    HC: HttpClient,
{
    #[instrument(level = Level::TRACE, skip(self), ret())]
    async fn create_authorization_request(
        &self,
        resolved_presentation_query: &ResolvedPresentationQuery,
        auth_response_config: &AuthResponseOptions,
        pass_auth_request_object: &PassAuthRequestObject,
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
                auth_response_config,
                pass_auth_request_object,
                wallet_metadata.unwrap_or(&default_wallet_metadata()),
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
    ) -> Result<Claims> {
        let authorization_response = self
            .resolve_authorization_response(authorization_response)
            .await?;

        let vp_token_claims = self
            .do_verify_presentation(
                &session.resolved_presentation_query,
                &session.nonce,
                &authorization_response,
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

        Ok(claims)
    }
}

impl<VF, KH, KMS, NG, HC> VerifierService<VF, KH, KMS, NG, HC>
where
    VF: vc::core::Verifier,
    KH: KeyHandle,
    KMS: Kms<KH>,
    NG: NonceHandler,
    HC: HttpClient,
{
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn resolve_authorization_response(
        &self,
        response: &AuthorizationResponse,
    ) -> Result<AuthorizationResponseObject> {
        match response {
            AuthorizationResponse::Plain(auth_response) => Ok(auth_response.to_owned()),
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
                let alg = kh.alg();
                let private_key = add_public_private_keys(kh, alg)?;
                let private_key_handle = get_private_key_handler(private_key, alg)?;

                let decoded = decrypt_jwe_payload(jwe_response, private_key_handle.as_ref())
                    .await
                    .map_err(|e| Internal {
                        source: AuthorizationResponseDecryptionSnafu {
                            details: format!(
                                "Error from one-core while decrypting the jwe response: {}",
                                e
                            ),
                        }
                        .build(),
                    })?;
                let claim_set: Value =
                    serde_json::from_slice(decoded.as_slice()).map_err(|e| Internal {
                        source: AuthorizationResponseDecryptionSnafu {
                            details: format!(
                                "Error while parsing the decrypted jwe payload: {}",
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
                let vp_token = claim_set
                    .get("vp_token")
                    .ok_or(Internal {
                        source: AuthorizationResponseDecryptionSnafu {
                            details: "Error: vp_token was not found".to_string(),
                        }
                        .build(),
                    })?
                    .to_owned();
                let presentation_submission = claim_set
                    .get("presentation_submission")
                    .and_then(|value: &Value| serde_json::from_value(value.to_owned()).ok());
                let id_token = claim_set
                    .get("id_token")
                    .and_then(|value: &Value| serde_json::from_value(value.to_owned()).ok());
                let state = claim_set
                    .get("state")
                    .and_then(|value: &Value| serde_json::from_value(value.to_owned()).ok());

                Ok(AuthorizationResponseObject {
                    vp_token,
                    presentation_submission,
                    id_token,
                    state,
                })
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
            id_token.audience == self.metadata.client_id,
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
        auth_response_config: &AuthResponseOptions,
        pass_auth_request_object: &PassAuthRequestObject,
        wallet_metadata: &WalletMetadata,
    ) -> Result<(Url, Option<String>)> {
        match &auth_response_config.mode {
            ResponseMode::DCAPIJwt | ResponseMode::DCAPI => {
                let client = RedirectUriClient::new(
                    ClientId::new(self.metadata.client_id.to_owned()).context(ClientIdSnafu)?,
                );
                let verifier_builder = openid4vp::verifier::Verifier::builder().with_client(client);
                self.build_authorization_request_helper(
                    resolved_presentation_query,
                    nonce,
                    auth_response_config,
                    pass_auth_request_object,
                    wallet_metadata,
                    verifier_builder,
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

                let did_client = DIDClient::new(
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
                    auth_response_config,
                    pass_auth_request_object,
                    wallet_metadata,
                    verifier_builder,
                )
                .await
            }
        }
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn build_authorization_request_helper(
        &self,
        presentation_definition: &ResolvedPresentationQuery,
        nonce: Nonce,
        auth_response_config: &AuthResponseOptions,
        pass_auth_request_object: &PassAuthRequestObject,
        wallet_metadata: &WalletMetadata,
        verifier_builder: openid4vp::verifier::VerifierBuilder<
            impl openid4vp::verifier::client::Client + WasmNotSend + WasmNotSync,
        >,
    ) -> Result<(Url, Option<String>)> {
        let auth_req_type = match (
            pass_auth_request_object.to_owned(),
            &auth_response_config.mode,
        ) {
            (PassAuthRequestObject::ByValue, ResponseMode::DCAPIJwt | ResponseMode::DCAPI) => {
                RequestType::Plain
            }
            (
                PassAuthRequestObject::ByValue,
                ResponseMode::DirectPost | ResponseMode::DirectPostJwt,
            ) => RequestType::SignedJwt(ByReference::False),
            (
                PassAuthRequestObject::ByReference { uri, method },
                ResponseMode::DirectPost | ResponseMode::DirectPostJwt,
            ) => RequestType::SignedJwt(ByReference::True(RequestReference {
                request_uri: uri,
                request_uri_method: method,
            })),
            (_, mode) => {
                return Err(Error::Protocol {
                    source: ProtocolError::invalid_request(
                        &format!(
                            "passing authorization request object by value or url is not supported in '{mode}' response mode"
                        ),
                        auth_response_config.state.clone(),
                    ),
                });
            }
        };

        let verifier = verifier_builder
            .with_submission_endpoint(auth_response_config.submission_uri.to_owned())
            .build()
            .await
            .context(Oid4VpLibSnafu)?;

        let request_builder = verifier.build_authorization_request();

        let request_builder = match auth_response_config.type_ {
            ResponseType::VpTokenIdToken => request_builder
                .with_request_parameter(auth_response_config.type_.to_owned())
                .with_request_parameter(Scope("openid".to_string()))
                .with_request_parameter(IdTokenType::SubjectSigned),
            _ => request_builder.with_request_parameter(auth_response_config.type_.to_owned()),
        };

        let pass_req_obj = match pass_auth_request_object.to_owned() {
            PassAuthRequestObject::ByValue => ByReference::False,
            PassAuthRequestObject::ByReference { uri, method } => {
                ByReference::True(RequestReference {
                    request_uri: uri,
                    request_uri_method: method,
                })
            }
        };

        let mut request_builder = match &auth_response_config.state {
            Some(state) => request_builder.with_request_parameter(State(state.to_string())),
            None => request_builder,
        };

        match presentation_definition {
            ResolvedPresentationQuery::PresentationDefinition(pd) => {
                request_builder = request_builder.with_presentation_definition(pd.clone());
            }
            ResolvedPresentationQuery::DCQL(dcql) => {
                request_builder = request_builder.with_dcql(dcql.clone());
            }
        }
        let (auth_request_url, auth_req_jwt) = request_builder
            .with_request_parameter(auth_response_config.mode.to_owned())
            .with_request_parameter(NonceSpruce::from(nonce.secret()))
            .with_request_parameter(self.metadata.client_metadata.clone())
            .build(wallet_metadata, auth_req_type)
            .await?;

        Ok((auth_request_url, auth_req_jwt))
    }

    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    async fn do_verify_presentation(
        &self,
        presentation_definition: &ResolvedPresentationQuery,
        nonce: &Nonce,
        authorization_response: &AuthorizationResponseObject,
    ) -> Result<Claim> {
        let mut result: HashMap<String, Claim> = HashMap::new();
        let mut ids = vec![]; // we need it to preserve order of items in the array

        let requested_presentations = match presentation_definition {
            ResolvedPresentationQuery::DCQL(dcql) => {
                dcql::resolve_presentation_response(authorization_response.vp_token.clone(), dcql)
                    .context(DCQLSnafu)?
            }
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
            let claims = self
                .verifier
                .verify_presentation(
                    nonce,
                    &requested_presentation.presentation,
                    &self.http_client,
                )
                .await
                .context(VCSnafu)?;

            ids.push(requested_presentation.id.clone());
            result.insert(requested_presentation.id, claims.into());
        }

        match authorization_response.vp_token {
            Json::Array(_) => {
                let mut arr = vec![];
                for id in ids.into_iter() {
                    arr.push(
                        result
                            .get(&id)
                            .unwrap()
                            .clone()
                            .try_into()
                            .context(ClaimsSnafu)?,
                    );
                }

                let claims = Json::Array(arr);
                match presentation_definition {
                    ResolvedPresentationQuery::PresentationDefinition(pd) => {
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
                    ResolvedPresentationQuery::DCQL(dcql) => {
                        //TODO maybe validate
                    }
                }
            }
            _ => {
                if let Some(claim) = result.values().find(|_| true) {
                    // TODO: figure out how to secure erase sensitive data
                    // after Claim -> Value convertation

                    match presentation_definition {
                        ResolvedPresentationQuery::PresentationDefinition(pd) => {
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
                        ResolvedPresentationQuery::DCQL(dcql) => {
                            //TODO maybe validate
                        }
                    }
                }
            }
        };

        Ok(Claim::Object(result))
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
    use crate::vc::oid4vp::tests::fixtures::multi_presentation::{
        auth_response_options, submission_requirements,
    };
    use crate::vc::oid4vp::tests::fixtures::{NONCE, multi_presentation, single_presentation};
    use crate::vc::oid4vp::tests::fixtures::{STATE, VERIFIER_URL};
    use crate::vc::oid4vp::tests::utils::{
        VerificationTestCase, build_url, validate_claims, verifier_service,
        verifier_service_with_invalid_kid, verifier_service_with_signer_error,
    };
    use crate::vc::oid4vp::verifier::VP_TOKEN;
    use crate::vc::oid4vp::{HttpMethodForAuth, InternalError, ResolvedAuthRequest};
    use crate::vc::oid4vp::{PassAuthRequestObject, PresentationSession, ResponseType, Verifier};
    use crate::vc::presentation_exchange::PresentationDefinition;
    use openid4vp::core::authorization_request::{
        AuthorizationRequest, AuthorizationRequestObject,
    };
    use openid4vp::core::object::UntypedObject;
    use openid4vp::wallet::IdTokenParams;
    use rstest::rstest;
    use serde_json::{from_value, json};
    use ssi::claims::jwt::decode_unverified;
    use std::collections::HashMap;
    use url::Url;
    fn get_metadata() -> ClientMetadata {
        let result: ResolvedAuthRequest = from_value(json!(
           {
              "response_uri": "https://some-link.com",
              "client_id": "some_id",
              "response_type": "vp_token",
              "response_mode": "dc_api.jwt",
              "nonce": "xyz123ltcaccescbwc777",
              "dcql_query": {
                "credentials": [
                  {
                    "id": "my_credential",
                    "format": "dc+sd-jwt",
                    "meta": {
                      "vct_values": [
                        "https://credentials.example.com/identity_credential"
                      ]
                    },
                    "claims": [
                      {
                        "path": [
                          "last_name"
                        ]
                      },
                      {
                        "path": [
                          "first_name"
                        ]
                      },
                      {
                        "path": [
                          "address",
                          "postal_code"
                        ]
                      }
                    ]
                  }
                ]
              },
              "client_metadata": {
                "jwks": {
                  "keys": [
                   {
                      "kid": "ecdsa-kid",
                      "kty": "EC",
                      "crv": "P-256",
                      "x": "SSnPfyVhQgcU9Aaynqgi6QGhrq7K7WFEC0mAvpHG4TM",
                       "y": "rYQ5mLQLTs95WLBKKA8R5IjMTXjX13iZnzazsVectRY",
                      "alg": "ECDSA"
                    }
                  ]
                },
                "encrypted_response_enc_values_supported": [
                  "A256GCM",
                ]
              }
           }
        ))
        .unwrap();

        result.client_metadata
    }

    #[tokio::test]
    async fn generate_auth_request_by_reference_success() {
        let presentation_definition = single_presentation::sd_jwt::presentation_definition();
        let request_uri = build_url(VERIFIER_URL, "request");
        let request_uri_method = "post";

        let (verifier, did) = verifier_service().await;

        let auth_resp_options = auth_response_options(build_url(VERIFIER_URL, "auth"), None);

        let (uri, _) = verifier
            .create_authorization_request(
                &presentation_definition,
                &auth_resp_options,
                &PassAuthRequestObject::ByReference {
                    uri: request_uri.clone(),
                    method: Some(HttpMethodForAuth::POST),
                },
                None,
            )
            .await
            .unwrap();

        let hash_query: HashMap<String, String> = uri.query_pairs().into_owned().collect();

        assert_eq!(hash_query.get("client_id").unwrap(), &did);
        assert_eq!(hash_query.get("request_uri").unwrap(), request_uri.as_str());
        assert_eq!(
            hash_query.get("request_uri_method").unwrap(),
            request_uri_method
        );
    }

    #[tokio::test]
    async fn auth_request_generating_fails_when_key_id_is_not_valid() {
        let presentation_definition = single_presentation::sd_jwt::presentation_definition();
        let request_uri = build_url(VERIFIER_URL, "request");
        let auth_resp_options = auth_response_options(build_url(VERIFIER_URL, "auth"), None);

        let (verifier, did) = verifier_service_with_invalid_kid().await;

        let result = verifier
            .create_authorization_request(
                &presentation_definition,
                &auth_resp_options,
                &PassAuthRequestObject::ByReference {
                    uri: request_uri,
                    method: None,
                },
                None,
            )
            .await;

        assert!(matches!(
            result.err().unwrap(),
            Error::Internal {
                source: InternalError::KMS { .. }
            }
        ));
    }

    #[tokio::test]
    async fn auth_request_generating_fails_in_case_of_signer_error() {
        let presentation_definition = single_presentation::sd_jwt::presentation_definition();
        let request_uri = build_url(VERIFIER_URL, "request");
        let auth_resp_options = auth_response_options(build_url(VERIFIER_URL, "auth"), None);

        let (verifier, did) = verifier_service_with_signer_error().await;

        let result = verifier
            .create_authorization_request(
                &presentation_definition,
                &auth_resp_options,
                &PassAuthRequestObject::ByReference {
                    uri: request_uri,
                    method: None,
                },
                None,
            )
            .await;

        assert!(matches!(
            result.err().unwrap(),
            Error::Internal {
                source: InternalError::Oid4VpLib { .. }
            }
        ));
    }

    #[tokio::test]
    async fn generate_auth_request_by_value_success() {
        let presentation_definition = single_presentation::sd_jwt::presentation_definition();
        let response_uri: Url = build_url(VERIFIER_URL, "auth");

        let (verifier, did) = verifier_service().await;

        let auth_resp_options = auth_response_options(response_uri.clone(), None);

        let (request_uri, session) = verifier
            .create_authorization_request(
                &presentation_definition,
                &auth_resp_options,
                &PassAuthRequestObject::ByValue,
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
        assert_eq!(request.client_id().get_id().to_owned(), did);
        assert_eq!(request.return_uri(), &response_uri);
    }

    #[tokio::test]
    async fn generate_auth_request_with_state_success() {
        let presentation_definition = single_presentation::sd_jwt::presentation_definition();
        let response_uri: Url = build_url(VERIFIER_URL, "auth");

        let (verifier, did) = verifier_service().await;

        let auth_resp_options =
            auth_response_options(response_uri.clone(), Some(STATE.to_string()));

        let (request_uri, session) = verifier
            .create_authorization_request(
                &presentation_definition,
                &auth_resp_options,
                &PassAuthRequestObject::ByValue,
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

        let (verifier, did) = verifier_service().await;

        let mut auth_resp_options = auth_response_options(response_uri.clone(), None);
        auth_resp_options.type_ = ResponseType::VpTokenIdToken;

        let (request_uri, session) = verifier
            .create_authorization_request(
                &presentation_definition,
                &auth_resp_options,
                &PassAuthRequestObject::ByValue,
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
        assert_eq!(request.client_id().get_id().to_owned(), did);
        assert_eq!(request.return_uri(), &response_uri);
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

        let auth_resp_options = auth_response_options(build_url(VERIFIER_URL, "auth"), None);

        let (request, _) = verifier
            .create_authorization_request(
                &ResolvedPresentationQuery::PresentationDefinition(presentation_definition),
                &auth_resp_options,
                &PassAuthRequestObject::ByReference {
                    uri: request_uri,
                    method: None,
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
        let kms = LocalKms::new();
        let session = PresentationSession {
            nonce: Nonce::from_secret(NONCE.to_owned()),
            resolved_presentation_query: test_case.session.resolved_presentation_query.clone(),
            auth_request_jwt: Default::default(),
        };

        let response = test_case.auth_response(&session.nonce, &client_id).await;

        let verified_claims = verifier
            .verify_presentation(&AuthorizationResponse::Plain(response), &test_case.session)
            .await
            .unwrap();

        validate_vp_token_against_expected_claims(test_case, &verified_claims);
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
            .verify_presentation(&AuthorizationResponse::Plain(response), &test_case.session)
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
        let kms = LocalKms::new();
        let nonce = Nonce::from_secret(NONCE.to_owned());

        let response = test_case.auth_response(&nonce, &client_id).await;

        let verified_claims = verifier
            .verify_presentation(&AuthorizationResponse::Plain(response), &test_case.session)
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
        let kms = LocalKms::new();
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
            .verify_presentation(&AuthorizationResponse::Plain(response), &test_case.session)
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

            let cred_claims = match &cred_claims {
                Claim::Object(map) => {
                    let mut claims = Claims::new();
                    map.iter()
                        .for_each(|(k, v)| claims.insert(k.to_owned(), v.to_owned()));
                    claims
                }
                _ => panic!("cred_claims is not an object"),
            };

            validate_claims(
                &ClaimFormatDesignation::SdJwtVc,
                &cred_claims,
                &credential_data,
            );
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
}
