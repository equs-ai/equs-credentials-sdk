use crate::did::DIDResolver;
use crate::vc;
use crate::vc::core::PresentationInput;
use crate::vc::oid4vp::presentation_exchange::split_to_inputs;
use crate::vc::oid4vp::{default_wallet_metadata, AuthorizationResponseMetadata, CredentialMapping, ResolvedAuthRequest};
use crate::vc::{oid4vp as api, Credential, Presentation};
use anyhow::bail;
use async_trait::async_trait;
use oid4vp::core::authorization_request::parameters::ClientMetadata;
use oid4vp::core::authorization_request::verification::RequestVerification;
use oid4vp::core::authorization_request::AuthorizationRequestObject;
use oid4vp::core::credential_format::CoreCredentialFormat;
use oid4vp::core::metadata::parameters::verifier::VpFormats;
use oid4vp::core::metadata::WalletMetadata;
use oid4vp::core::object::{ParsingErrorContext, UntypedObject};
use oid4vp::core::profile;
use oid4vp::core::profile::Wallet;
use oid4vp::core::response::parameters::{PresentationSubmission as PresentationSubmissionParam, VpToken};
use oid4vp::core::response::AuthorizationResponse;
use oid4vp::presentation_exchange::{DescriptorMap, PresentationSubmission};
use url::Url;
use uuid::Uuid;

pub type Error = api::HolderError;
pub type Result<T> = core::result::Result<T, Error>;

pub struct HolderService<HL, D>
where
    HL: vc::core::Holder,
    D: DIDResolver,
{
    holder: HL,
    did_resolver: D,
    metadata: WalletMetadata,
    http_client: reqwest::Client,
}

impl<HL, D> HolderService<HL, D>
where
    HL: vc::core::Holder,
    D: DIDResolver,
{
    pub fn new(
        holder: HL,
        did_resolver: D,
        metadata: Option<WalletMetadata>,
        http_client: reqwest::Client,
    ) -> Self {
        let metadata = metadata.unwrap_or(default_wallet_metadata());

        Self {
            holder,
            metadata,
            did_resolver,
            http_client,
        }
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
        // TODO: implement builder-like helper for VpToken/PresentationSubmission in presentation_exchange
        let presentation = self.holder.create_presentation(
            nonce,
            client_id,
            presentation_input,
            credential,
        ).await?;

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
        mut pres_sub: PresentationSubmission,
    ) -> Result<AuthorizationResponse> {
        // TODO: refactor and move to presentation_exchange
        let mut response_params = UntypedObject::default();

        if presentations.len() == 1 {
            let vp_token = serde_json::from_value(
                serde_json::to_value(&presentations[0])?
            )?;
            response_params.insert(VpToken(vp_token));
            pres_sub.descriptor_map[0].path = "$".to_owned();
        } else {
            let vp_token = serde_json::to_string(&presentations)?;
            response_params.insert(VpToken(vp_token));
        };

        let pres_sub_json = serde_json::to_value(pres_sub)?;
        response_params.insert(PresentationSubmissionParam(pres_sub_json));

        let auth_resp = AuthorizationResponse::try_from(response_params)?;

        Ok(auth_resp)
    }
}

#[async_trait]
impl<HL, D> api::Holder for HolderService<HL, D>
where
    HL: vc::core::Holder,
    D: DIDResolver,
{
    async fn get_authorization_request(
        &self,
        auth_req_uri: &str,
    ) -> Result<ResolvedAuthRequest> {
        let url = Url::parse(auth_req_uri)?;
        let aro = self.handle_request(&url, &self.http_client).await?;

        let pres_def = aro.resolve_presentation_definition()
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

    async fn present_credentials_auto(
        &self,
        auth_request: &ResolvedAuthRequest,
        _: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>> {
        let mut vp_tokens = vec![];
        let mut pres_sub = PresentationSubmission {
            id: Uuid::new_v4().to_string(),
            definition_id: auth_request.presentation_definition.id.clone(),
            descriptor_map: vec![],
        };

        let pres_inputs = split_to_inputs(&auth_request.presentation_definition)?;

        for (i, pres_input) in pres_inputs.iter().enumerate() {
            let creds = self.holder.find_vcs_for_presentation(pres_input).await?;

            // TODO: run in parallel
            self.submit_auth_response_helper(
                auth_request.nonce.0.as_str(),
                auth_request.client_id.as_str(),
                pres_input,
                creds.first().ok_or(Error::CredentialNotFound)?,
                format!("$[{i}]"),
                &mut vp_tokens,
                &mut pres_sub,
            ).await?;
        }

        let auth_resp = Self::generate_auth_response(vp_tokens, pres_sub)?;
        let redirect_url = self.submit_response(
            &auth_request.response_uri,
            &auth_request.response_mode,
            auth_resp,
            &self.http_client,
        ).await?;

        Ok(redirect_url)
    }

    async fn find_vcs_for_presentation(&self, auth_request: &ResolvedAuthRequest) -> Result<CredentialMapping> {
        let mut creds_map = CredentialMapping::new();

        let pres_inputs = split_to_inputs(&auth_request.presentation_definition)?;
        for pres_input in pres_inputs.iter() {
            let creds = self.holder.find_vcs_for_presentation(pres_input).await?;
            creds_map.insert(pres_input.id.to_owned(), creds);
        }

        Ok(creds_map)
    }

    async fn present_credentials(
        &self,
        auth_request: &ResolvedAuthRequest,
        creds_map: &CredentialMapping,
        _: &AuthorizationResponseMetadata,
    ) -> Result<Option<Url>> {
        let mut vp_tokens = vec![];
        let mut pres_sub = PresentationSubmission {
            id: Uuid::new_v4().to_string(),
            definition_id: auth_request.presentation_definition.id.clone(),
            descriptor_map: vec![],
        };

        let mut path_index: usize = 0;
        let pres_inputs = split_to_inputs(&auth_request.presentation_definition)?;
        for pres_input in pres_inputs.iter() {
            // TODO: refactor `path_index` logic and run async code in parallel
            if let Some(creds) = creds_map.get(&pres_input.id) {
                for cred in creds.iter() {
                    self.submit_auth_response_helper(
                        auth_request.nonce.0.as_str(),
                        auth_request.client_id.as_str(),
                        pres_input,
                        cred,
                        format!("$[{path_index}]"),
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
        let redirect_url = self.submit_response(
            &auth_request.response_uri,
            &auth_request.response_mode,
            auth_resp,
            &self.http_client,
        ).await?;

        Ok(redirect_url)
    }
}

#[async_trait]
impl<HL, D> profile::Profile for HolderService<HL, D>
where
    HL: vc::core::Holder,
    D: DIDResolver,
{
    type CredentialFormat = CoreCredentialFormat;

    async fn validate_request(
        &self,
        wallet_metadata: &WalletMetadata,
        request_object: &AuthorizationRequestObject,
    ) -> anyhow::Result<()> {
        if request_object.get::<ClientMetadata>().is_none() {
            return Ok(());
        }

        let client_metadata = ClientMetadata::resolve(request_object)
            .await
            .parsing_error()?;

        if let Some(Ok(vp_formats)) = client_metadata.0.get::<VpFormats>() {
            let unsupported = vp_formats.0
                .keys()
                .find(|k| !wallet_metadata.vp_formats_supported().0.contains_key(*k));
            if let Some(format) = unsupported
            {
                bail!("vp format not supported");
            }
        }

        Ok(())
    }
}

#[async_trait]
impl<HL, D> Wallet for HolderService<HL, D>
where
    HL: vc::core::Holder,
    D: DIDResolver,
{
    fn wallet_metadata(&self) -> &WalletMetadata {
        &self.metadata
    }
}

#[async_trait]
impl<HL, D> RequestVerification for HolderService<HL, D>
where
    HL: vc::core::Holder,
    D: DIDResolver,
{
    async fn did(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        let (header, _) = ssi::jws::decode_unverified(&request_jwt)?;

        let kid = header.key_id.ok_or(
            Error::RequestObjectVerification("could not parse kid from Request Object JWT".to_owned())
        )?;
        let ver_map = self.did_resolver.resolve_verification_method(kid.as_str()).await?;
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
    ) -> anyhow::Result<()> {
        //TODO: Implement verification method
        Ok(())
    }

    async fn preregistered(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        //TODO: Implement verification method
        Ok(())
    }

    async fn redirect_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        //TODO: Implement verification method
        Ok(())
    }

    async fn x509_san_dns(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        //TODO: Implement verification method
        Ok(())
    }

    async fn x509_san_uri(
        &self,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        //TODO: Implement verification method
        Ok(())
    }

    async fn other(
        &self,
        client_id_scheme: &str,
        decoded_request: &AuthorizationRequestObject,
        request_jwt: String,
    ) -> anyhow::Result<()> {
        //TODO: Implement verification method
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::crypto::{Alg, Key};
    use crate::did::didkey::DIDKey;
    use crate::did::DIDURL;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::kms::Kms;
    use crate::vault::Vault;
    use crate::vc::core::{HolderMetadata, KeyMetadata};
    use crate::vc::{Credential, CredentialMetadata, VCFormat};
    use crate::{kms, vc};
    use std::str::FromStr;

    use crate::vc::oid4vp as api;
    use crate::vc::oid4vp::holder::HolderService;
    use crate::vc::oid4vp::AuthorizationResponseMetadata;
    use crate::vc::oid4vp::Holder;

    const REQUEST_OBJECT: &str = "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVhZ3ZXMmVEV2MyeVZ3N0I5OG92Y0o4amRkbjdUOU1oM3k1VmlreXM2eTRrWCN6RG5hZWFndlcyZURXYzJ5Vnc3Qjk4b3ZjSjhqZGRuN1Q5TWgzeTVWaWt5czZ5NGtYIiwidHlwIjoiSldUIn0.eyJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV91cmkiOiJodHRwOi8vMTI3LjAuMC4xOjU1Nzk2L2F1dGgiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJub25jZSI6Im4wTmNFIiwiY2xpZW50X21ldGFkYXRhIjp7InZwX2Zvcm1hdHMiOnsidmMrc2Qtand0Ijp7ImFsZyI6WyJFZERTQSIsIkVTMjU2Il19fX0sInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMWI5ZDZiY2QtYmJmZC00YjJkLTliNWQtYWI4ZGZiYmQ0YmVkIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiSWRlbnRpdHktMSIsIm5hbWUiOiJJZGVudGl0eSBWQyIsInB1cnBvc2UiOiJXZSB3YW50IGFuIGlkZW50aXR5IiwiZm9ybWF0Ijp7InZjK3NkLWp3dCI6eyJhbGciOlsiRWREU0EiLCJFUzI1NksiXX19LCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC52Y3QiXSwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJjb25zdCI6Imh0dHBzOi8vY3JlZGVudGlhbHMuZXhhbXBsZS5jb20vaWRlbnRpdHlfY3JlZGVudGlhbCJ9fSx7InBhdGgiOlsiJC5uYW1lIl19XX19XX0sImNsaWVudF9pZCI6ImRpZDprZXk6ekRuYWVhZ3ZXMmVEV2MyeVZ3N0I5OG92Y0o4amRkbjdUOU1oM3k1VmlreXM2eTRrWCIsImNsaWVudF9pZF9zY2hlbWUiOiJkaWQifQ.RlrD5ibioAvM_S0QAhdPK--9WyLEw258cMduAn26S1puXIxKgJod9gt00FDrK0x-jdPmkuPdpJWKzg3kcimIVQ";
    const REQUEST_URI: &str = "openid4vp://?client_id=did%3Akey%3AzDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX&request_uri=http%3A%2F%2F127.0.0.1%3A55796%2Frequest";
    const CLIENT_ID: &str = "wallet-dev";
    const CRED_JWT: &str = "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiJ9.eyJfc2QiOlsiSDQyTEp5b1JtWFhybktOUUZDWFcxb3BnRURtZ05hUFlsLUVyV3lxWkNXNCIsIlVOd19fd3hQSzdIbWk3LVZvdjBpaUZvc2Y2bUFCNlM2MzdTd3BqdlRWbDgiLCJlX2NaMVFCSGV4Z3ZBUUdfOF9BdkVNX3U4amJfTi1MOVFTdXdaMkhKVTFFIl0sInZjdCI6Imh0dHBzOi8vY3JlZGVudGlhbHMuZXhhbXBsZS5jb20vaWRlbnRpdHlfY3JlZGVudGlhbCIsImRhdGUiOiIwOS8wOS8xOTg5Iiwic3ViIjoiZGlkOmtleTp6RG5hZWRTWUZWcVpqc3NyckxjamRCWVBHR0RTMm92U3JvRWl5ZFVQOHNEQk5lN3lDIiwibmJmIjoxNzI0MzcyNTY4LCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ekRuYWVWZUFYdGRneExab0d4VkFNUEZUN0pBZGhpUFZXckNxeVJiNVJzVWFnU0NVZSIsImlhdCI6MTcyNDM3MjU2OCwiZXhwIjoxNzU1OTA4NTY4LCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4Ijoid1UxNWZwa3F3bDdxV3RKV2tZUmJmQTlMQ0Z3SFJKX21yQkJhOXEyU0ZPcyIsInkiOiJUaFBhVHZTQW9mdUYtNFpzbjg2RllHRGtLTHZhd2Z3TXlLZmc5bTJJaTlnIn19fQ.s_s2RV6dHjW4JnwlYozGgrTvrjcr7E1BTutHI8OgP9jDjwIH9sM17339QwZrONY_QkcRiCBpIEVK-9OPESNqQg~WyJFR0lvZ0d2UVY5c0liZzlDSW1KU0Z3IiwgIm5hbWUiLCAiSm9obiJd~WyJxZTZoTjMyVFFyY09CYWVWSERpcE1nIiwgInN1cm5hbWUiLCAiRG9lIl0~WyJtUzRuS2FHMjRXdVdpMTlaWHB6VG5RIiwgImFkZHJlc3MiLCAiMjIxQiBCYWtlciBTdHJlZXQiXQ~";

    #[tokio::test]
    async fn e2e() {
        let mut verifier_srv = mockito::Server::new_with_opts(mockito::ServerOpts {
            host: "127.0.0.1",
            port: 55796,
            assert_on_drop: false,
        });

        verifier_srv
            .mock("GET", "/request")
            .with_header("content-type", "text/plain")
            .with_status(200)
            .with_body(REQUEST_OBJECT)
            .create();
        verifier_srv
            .mock("POST", "/auth")
            .with_status(200)
            .create();

        let holder = oid4vp_holder().await;
        // Handle request object
        let request_obj = holder
            .get_authorization_request(REQUEST_URI)
            .await
            .unwrap();
        // Send auth response
        holder.present_credentials_auto(&request_obj, &AuthorizationResponseMetadata {})
            .await
            .unwrap();
    }

    async fn oid4vp_holder() -> impl api::Holder {
        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .https_only(false)
            .build()
            .unwrap();
        let inner = holder().await;
        let resolver = DIDKey::new();
        HolderService::new(
            inner,
            resolver,
            None,
            client,
        )
    }

    async fn holder() -> impl vc::core::Holder {
        let kms = LocalKms::new();
        let didkey = DIDKey::new();
        let vault = InMemVault::new();

        let cred1_meta = CredentialMetadata { type_: "https://credentials.example.com/identity_credential".into(), format: VCFormat::SdJwtVc, alg: Some(Alg::ES256), tags: vec![] };
        let store1_res = vault.store_credential(Credential::SdJwt(CRED_JWT.to_string()), &cred1_meta).await;
        assert!(store1_res.is_ok());

        let kt = kms::KeyType::P256;
        let (kid, kh) = kms.create_and_handle(kt, kms::CreateOptions {}).await.unwrap();

        let did = didkey.generate(kh.clone()).unwrap();
        let did_url = DIDURL::from_str(&did).unwrap();
        println!("DID: {}", did);

        let jwk = kh.clone().jwk().unwrap();
        println!("Key JWK:\n{}", serde_json::to_string_pretty(&jwk).unwrap());

        vc::core::HolderService::new(kms, vault, HolderMetadata {
            client_id: CLIENT_ID.to_owned(),
            key_metadata: KeyMetadata {
                did_url: did_url.to_string(),
                kid: kid.clone(),
            },
        })
    }
}