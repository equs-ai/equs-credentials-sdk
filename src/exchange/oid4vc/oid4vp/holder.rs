use core::str;
use std::collections::HashMap;

use anyhow::bail;
use async_trait::async_trait;
use oid4vp::core::authorization_request::AuthorizationRequestObject;
use oid4vp::core::authorization_request::parameters::{ClientMetadata, Nonce, ResponseMode};
use oid4vp::core::authorization_request::verification::RequestVerification;
use oid4vp::core::credential_format::CoreCredentialFormat;
use oid4vp::core::metadata::parameters::verifier::VpFormats;
use oid4vp::core::metadata::WalletMetadata;
use oid4vp::core::object::{ParsingErrorContext, UntypedObject};
use oid4vp::core::profile;
use oid4vp::core::profile::Wallet;
use oid4vp::core::response::AuthorizationResponse;
use oid4vp::presentation_exchange::{
    DescriptorMap, PresentationDefinition, PresentationSubmission,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::Url;
use uuid::Uuid;

use crate::core_::did::DIDResolver;
use crate::core_::vc::Credential;
use crate::exchange::oid4vc::oid4vp::default_wallet_metadata;
use crate::facade::facade_low_level;
use crate::facade::facade_low_level::{Holder, Presentation, PresentationInput};

pub struct Oid4VpHolder {
    holder: Box<dyn Holder>,
    metadata: WalletMetadata,
    did_resolver: Box<dyn DIDResolver>,
    http_client: reqwest::Client,
}

impl Oid4VpHolder {
    pub fn new(
        metadata: Option<WalletMetadata>,
        holder: impl Holder + 'static,
        did_resolver: impl DIDResolver + 'static,
        http_client: reqwest::Client,
    ) -> Self {
        let metadata = if let Some(metadata) = metadata {
            metadata
        } else {
            default_wallet_metadata()
        };

        Self {
            holder: Box::new(holder),
            metadata,
            did_resolver: Box::new(did_resolver),
            http_client,
        }
    }
    pub async fn resolve_authorization_request(&self, url: &Url) -> Result<ResolvedAuthRequest> {
        let aro = self.handle_request(url, &self.http_client).await?;

        let pres_def = aro
            .resolve_presentation_definition()
            .await?
            .parsed()
            .to_owned();

        Ok(ResolvedAuthRequest {
            client_id: aro.client_id().0.to_owned(),
            presentation_definition: pres_def,
            nonce: aro.nonce().clone(),
            response_mode: aro.response_mode().to_owned(),
            response_uri: aro.return_uri().to_owned(),
        })
    }

    pub async fn submit_authorization_response(
        &self,
        resolved_request: &ResolvedAuthRequest,
    ) -> Result<Option<Url>> {
        let mut vp_tokens = vec![];
        let mut pres_sub = PresentationSubmission {
            id: Uuid::new_v4().to_string(),
            definition_id: resolved_request.presentation_definition.id.clone(),
            descriptor_map: vec![],
        };

        for (i, pres_input) in resolved_request.to_presentation_inputs()?.iter().enumerate() {
            let creds = self.holder.find_vcs_for_presentation(pres_input).await?;

            self.submit_auth_response_helper(
                resolved_request.nonce.0.as_str(),
                resolved_request.client_id.as_str(),
                pres_input,
                creds.first().ok_or(Error::CredentialNotFound)?,
                format!("$[${i}]"),
                &mut vp_tokens,
                &mut pres_sub,
            )
                .await?;
        }

        let auth_resp = Self::generate_auth_response(vp_tokens, pres_sub)?;
        let redirect_url = self
            .submit_response(
                &resolved_request.response_uri,
                &resolved_request.response_mode,
                auth_resp,
                &self.http_client,
            )
            .await?;

        Ok(redirect_url)
    }

    pub async fn submit_authorization_response_selected(
        &self,
        resolved_request: &ResolvedAuthRequest,
        creds_map: &CredentialsMap,
    ) -> Result<Option<Url>> {
        let prs_inputs = resolved_request.to_presentation_inputs()?;
        let mut vp_tokens = vec![];
        let mut pres_sub = PresentationSubmission {
            id: Uuid::new_v4().to_string(),
            definition_id: resolved_request.presentation_definition.id.clone(),
            descriptor_map: vec![],
        };

        let mut path_index: usize = 0;
        for pres_input in prs_inputs.iter() {
            if let Some(creds) = creds_map.get(&pres_input.id) {
                for cred in creds.iter() {
                    self.submit_auth_response_helper(
                        resolved_request.nonce.0.as_str(),
                        resolved_request.client_id.as_str(),
                        pres_input,
                        cred,
                        format!("$[${path_index}]"),
                        &mut vp_tokens,
                        &mut pres_sub,
                    )
                        .await?;

                    path_index += 1;
                }
            } else {
                //TODO Implement cases when credentials not found
            }
        }

        let auth_resp = Self::generate_auth_response(vp_tokens, pres_sub)?;
        let redirect_url = self
            .submit_response(
                &resolved_request.response_uri,
                &resolved_request.response_mode,
                auth_resp,
                &self.http_client,
            )
            .await?;

        Ok(redirect_url)
    }

    async fn submit_auth_response_helper(
        &self,
        nonce: &str,
        client_id: &str,
        presentation_input: &PresentationInput,
        credential: &Credential,
        path: String,
        vp_tokens: &mut Vec<Presentation>,
        presentation_submission: &mut PresentationSubmission,
    ) -> Result<()>
    {
        let presentation = self
            .holder
            .create_presentation(
                nonce,
                client_id,
                presentation_input,
                credential,
            )
            .await?;

        vp_tokens.push(presentation);

        presentation_submission.descriptor_map.push(DescriptorMap {
            id: presentation_input.id.to_owned(),
            format: presentation_input.format.to_owned(),
            path,
        });

        Ok(())
    }

    fn generate_auth_response(
        presentations: Vec<Presentation>,
        pres_sub: PresentationSubmission,
    ) -> Result<AuthorizationResponse> {
        let mut prs_resp = PresentationResponse {
            vp_token: Default::default(),
            presentation_submission: pres_sub
        };

        if presentations.len() == 1 {
            prs_resp.vp_token = serde_json::to_value(presentations[0].clone())?;
            prs_resp.presentation_submission.descriptor_map[0].path = "$".to_owned();
        } else {
            prs_resp.vp_token = serde_json::to_value(presentations)?;
        };

        let un_ob: UntypedObject = serde_json::from_value(
            serde_json::to_value(prs_resp)?
        )?;
        let auth_resp = AuthorizationResponse::try_from(un_ob)?;

        Ok(auth_resp)
    }

    pub async fn get_vcs_for_presentation(&self, resolved_request: &ResolvedAuthRequest) -> Result<CredentialsMap> {
        let mut creds_map = CredentialsMap::new();

        for pres_input in resolved_request.to_presentation_inputs()?.iter() {
            let creds = self.holder.find_vcs_for_presentation(pres_input).await?;
            creds_map.insert(pres_input.id.to_owned(), creds);
        }

        Ok(creds_map)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PresentationResponse {
    vp_token: Value,
    presentation_submission: PresentationSubmission
}

pub type CredentialId = String;
pub type CredentialsMap = HashMap<CredentialId, Vec<Credential>>;

#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    #[error("vp format not supported")]
    VpFormatNotSupported,
    #[error("credential does not exist")]
    CredentialNotFound,
    #[error("could not parse vp-format from presentation definition")]
    VpFormatParse,
    #[error("could not validate Verifier: {0}")]
    RequestObjectVerification(String),
    #[error(transparent)]
    SpruceOid4Vp(#[from] anyhow::Error),
    #[error(transparent)]
    SpruceSsiJws(#[from] ssi::jws::Error),
    #[error(transparent)]
    Parse(#[from] serde_json::Error),
    #[error(transparent)]
    FacadeLowLevel(#[from] facade_low_level::Error),
    #[error("{0}")]
    Other(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolvedAuthRequest {
    pub client_id: String,
    pub presentation_definition: PresentationDefinition,
    pub nonce: Nonce,
    pub response_mode: ResponseMode,
    pub response_uri: Url,
}

impl ResolvedAuthRequest {
    pub fn to_presentation_inputs(&self) -> Result<Vec<PresentationInput>> {
        let mut prs_inputs: Vec<PresentationInput> = vec![];

        for desc in self.presentation_definition.input_descriptors.iter() {
            let claims: Vec<(String, Value)> = desc
                .constraints
                .fields
                .clone()
                .iter()
                .map(|constraints| {
                    constraints
                        .iter()
                        .map(|c| c.path.iter()
                            .map(|p| {
                                //TODO: Implement parsing nested fields like $.address.street
                                let paths: Vec<&str> = p.split(".").collect();
                                let top_level_claim = paths
                                    .get(1)
                                    .unwrap_or(&"");
                                (top_level_claim.to_string(), Value::Bool(true))
                            })
                        )
                        .flatten()
                })
                .flatten()
                .filter(|v| !v.0.is_empty())
                .collect();

            let claims = Map::from_iter(claims.into_iter());

            let format = desc.format.clone()
                .ok_or(Error::VpFormatParse)?
                .as_object()
                .to_owned()
                .and_then(|v| v.keys().find(|s| !s.is_empty()))
                .ok_or(Error::VpFormatParse)?.to_owned();

            prs_inputs.push(PresentationInput {
                id: desc.id.to_owned(),
                format,
                claims,
            });
        }

        return Ok(prs_inputs);
    }
}

pub type Result<T> = core::result::Result<T, Error>;
type Result_<T> = core::result::Result<T, anyhow::Error>;

#[async_trait]
impl profile::Profile for Oid4VpHolder {
    type CredentialFormat = CoreCredentialFormat;

    async fn validate_request(
        &self,
        wallet_metadata: &WalletMetadata,
        request_object: &AuthorizationRequestObject,
    ) -> Result_<()> {
        if request_object.get::<ClientMetadata>().is_some() {
            let client_metadata = ClientMetadata::resolve(request_object)
                .await
                .parsing_error()?;

            if let Some(Ok(vp_formats)) = client_metadata.0.get::<VpFormats>() {
                if let Some(format) = vp_formats
                    .0
                    .keys()
                    .find(|k| !wallet_metadata.vp_formats_supported().0.contains_key(*k))
                {
                    bail!("vp format not supported");
                }
            }
        }

        Ok(())
    }
}

#[async_trait]
impl profile::Wallet for Oid4VpHolder {
    fn wallet_metadata(&self) -> &WalletMetadata {
        &self.metadata
    }
}

#[async_trait]
impl RequestVerification for Oid4VpHolder {
    async fn did(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result_<()> {
        let (header, _) = ssi::jws::decode_unverified(&request_jwt)?;

        let kid = header.key_id.ok_or(
            Error::RequestObjectVerification("could not parse kid from Request Object JWT".to_owned())
        )?;
        let ver_map = self.did_resolver.resolve_verification_method(kid.as_str()).await.unwrap();
        let verifier_pub_jwk = &ver_map.public_key_jwk.ok_or(
            Error::RequestObjectVerification("could not parse Verifier's public JWK from Verification Method's Map".to_owned())
        )?;

        ssi::jws::decode_verify(&request_jwt, verifier_pub_jwk)?;

        Ok(())
    }

    async fn entity_id(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result_<()> {
        //TODO: Implement verification method
        Ok(())
    }

    async fn preregistered(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result_<()> {
        //TODO: Implement verification method
        Ok(())
    }

    async fn redirect_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result_<()> {
        //TODO: Implement verification method
        Ok(())
    }

    async fn x509_san_dns(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result_<()> {
        //TODO: Implement verification method
        Ok(())
    }

    async fn x509_san_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result_<()> {
        //TODO: Implement verification method
        Ok(())
    }

    async fn other(
        &self,
        client_id_scheme: &str,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> Result_<()> {
        //TODO: Implement verification method
        Ok(())
    }
}


#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use url::Url;

    use crate::core_::crypto::{Alg, Key};
    use crate::core_::did::DIDURL;
    use crate::core_::kms;
    use crate::core_::kms::Kms;
    use crate::core_::vault::Vault;
    use crate::core_::vc::{Credential, CredentialMetadata, VCFormat};
    use crate::exchange::oid4vc::oid4vp::default_wallet_metadata;
    use crate::exchange::oid4vc::oid4vp::holder::Oid4VpHolder;
    use crate::facade::facade_low_level;
    use crate::facade::facade_low_level::{HolderMetadata, HolderService, KeyMetadata};
    use crate::impls::did::didkey::DIDKey;
    use crate::impls::kms::inmem::LocalKms;
    use crate::impls::vault::inmem::InMemVault;

    const REQUEST_OBJECT: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVZckVtQzdXcDRQTmhyQVhoTnhvYUVHbVRkM3ppVEtjbjh6YjNwZ3BVdkFzViN6RG5hZVlyRW1DN1dwNFBOaHJBWGhOeG9hRUdtVGQzemlUS2NuOHpiM3BncFV2QXNWIiwidHlwIjoiSldUIn0.eyJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV91cmkiOiJodHRwOi8vMTI3LjAuMC4xOjU1Nzk2L3ByZXNlbnQiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJub25jZSI6Im4wTmNFIiwiY2xpZW50X21ldGFkYXRhIjp7InZwX2Zvcm1hdHMiOnsidmMrc2Qtand0Ijp7ImFsZyI6WyJFZERTQSIsIkVTMjU2SyJdfX19LCJwcmVzZW50YXRpb25fZGVmaW5pdGlvbiI6eyJpZCI6IjFiOWQ2YmNkLWJiZmQtNGIyZC05YjVkLWFiOGRmYmJkNGJlZCIsImlucHV0X2Rlc2NyaXB0b3JzIjpbeyJpZCI6IklkZW50aXR5LTEiLCJuYW1lIjoiSWRlbnRpdHkgVkMiLCJwdXJwb3NlIjoiV2Ugd2FudCBhIElkZW50aXR5IiwiZm9ybWF0Ijp7InZjK3NkLWp3dCI6eyJhbGciOlsiRWREU0EiLCJFUzI1NksiXX19LCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC5kb2IiXSwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJwYXR0ZXJuIjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIn19XX19XX0sImNsaWVudF9pZCI6ImRpZDprZXk6ekRuYWVZckVtQzdXcDRQTmhyQVhoTnhvYUVHbVRkM3ppVEtjbjh6YjNwZ3BVdkFzViIsImNsaWVudF9pZF9zY2hlbWUiOiJkaWQifQ.GbMZDDhsqAQpp7c4-sQDHBxVi83dBbgGqmQkQKJz-h8kV5OSnhyziv1BEHf6_KaUtjZuWMSlQBbIrIySgI_jvw";
    const REQUEST_URI: &str = "openid4vp://?client_id=did%3Akey%3AzDnaeYrEmC7Wp4PNhrAXhNxoaEGmTd3ziTKcn8zb3pgpUvAsV&request_uri=http%3A%2F%2F127.0.0.1%3A55796%2Frequest";
    const CLIENT_ID: &str = "wallet-dev";
    const CRED_JWT: &str = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiTTZqdURxUHFOMXJHdVlxcm9CNG9VNVB1bWItMW15VlZ3bGQzcjJ2NWdCSSIsInpsTEczNXoyekFCRXl2SElTdVhLZGFHa1FQOWhrSGs2V055ZVJaclc0cjQiXSwidmN0IjoiU0RfSldUX2NyZWQiLCJ0eXBlIjpbIlNEX0pXVF9jcmVkIl0sImRvYiI6IjA5LzA5LzE5ODkiLCJzdWIiOiJkaWQ6a2V5OnpEbmFleEM5RE55dVZ3M2p5a3V5WW1KZkJCU1pxWnZoNDZaZGdLbUxwemRjNWdKQVciLCJuYmYiOjE3MjI1NTgzMzAsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZVd2dER6R29TRVY1N2FIeFJVWDdkZUFVQjhvTHNTQmIyRE1Ua3V1NjZOYVY2IiwiaWF0IjoxNzIyNTU4MzMwLCJleHAiOjE3NTQwOTQzMzAsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiIxLXRZN2lfbW9MdUh6THljUlR3UUZBa0xoUXNvUFdxdXJvNEUwUnllYTBNIiwieSI6IjE5czVrQkpKTktXQmJIQXJyZzQ2RW56V1NBOGMwSm1VRWEwQ0lKa25zUnMifX19.Q675XX4fvAdZQcfZtdxQbzlN2l3q_jHV_ysDRgeD1HsSHVeZLHOuTn7G7JGxXTswmSkaDFljYF2yMeZWCwovrQ~WyIwWFNHek82d3p0cWUwM0VwVG8tTjJnIiwgImdpdmVuX25hbWUiLCAiSm9obiJd~WyJhTklXY0FfQWNmb19Hd0t1R3ZrZjZnIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd~";

    #[tokio::test]
    async fn e2e() {
        let mut verifier_srv = mockito::Server::new_with_opts(mockito::ServerOpts {
            host: "127.0.0.1",
            port: 55796,
            assert_on_drop: false,
        });

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .https_only(false)
            .build()
            .unwrap();
        let inner = holder().await;
        let resolver = DIDKey::new();
        let holder = Oid4VpHolder::new(
            Some(default_wallet_metadata()),
            inner,
            resolver,
            client,
        );

        let req_obj_mock = verifier_srv
            .mock("GET", "/request")
            .with_header("content-type", "text/plain")
            .with_status(200)
            .with_body(REQUEST_OBJECT)
            .create();
        // Handle request object
        let request_obj = holder
            .resolve_authorization_request(&Url::parse(REQUEST_URI).unwrap())
            .await
            .unwrap();

        let req_obj_mock = verifier_srv
            .mock("POST", "/present")
            .with_status(200)
            .create();
        // Send auth response
        holder
            .submit_authorization_response(&request_obj)
            .await
            .unwrap();
    }


    async fn holder() -> impl facade_low_level::Holder {
        let mut kms = LocalKms::new();
        let didkey = DIDKey::new();
        let mut vault = InMemVault::new();

        let cred1_meta = CredentialMetadata { id: "Identity-1".into(), format: VCFormat::SdJwtVc, alg: Alg::ES256 };
        let store1_res = vault.store_credential(Credential::SdJwt(CRED_JWT.to_string()), &cred1_meta).await;
        assert!(store1_res.is_ok());

        let kt = kms::KeyType::P256;
        let (kid, kh) = kms.create_and_handle(kt, kms::CreateOptions {}).await.unwrap();

        let did = didkey.generate(kh.clone()).unwrap();
        let did_url = DIDURL::from_str(&did).unwrap();
        println!("DID: {}", did);

        let jwk = kh.clone().jwk().unwrap();
        println!("Key JWK:\n{}", serde_json::to_string_pretty(&jwk).unwrap());

        HolderService::new(kms, vault, HolderMetadata {
            client_id: CLIENT_ID.to_owned(),
            key_metadata: KeyMetadata {
                did_url: did_url.to_string(),
                kid: kid.clone(),
            },
        })
    }
}