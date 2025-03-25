use crate::common::JsonValue;
use crate::common::{Error, Result};
use crate::utils::parse_url_arg;
use agent_sdk::inmem::kms::LocalKms;
use agent_sdk::inmem::vault::InMemVault;
use agent_sdk::kms::Kms;
use agent_sdk::reqwest::builder::ReqwestClientBuilder;
use agent_sdk::vault::Vault;
use agent_sdk::vc::oid4vp::{
    CredentialMapping, CredentialsMapping, Holder, ResolvedAuthRequest, Url,
};
use agent_sdk::vc::{oid4vp, HasVCFormat};
use agent_sdk::{kms, vc};
use std::collections::HashMap;

/// The `OID4VP` `Holder` API.
///
/// Supports presentation flow according to the `OID4VP` specification.
/// See <https://openid.net/specs/openid-4-verifiable-presentations-1_0-ID2.html>.
///
/// @property getAuthorizationRequest - {@link OID4VPHolder.getAuthorizationRequest}
/// @property presentCredentialsAuto - {@link OID4VPHolder.presentCredentialsAuto}
/// @property findVcsForPresentation - {@link OID4VPHolder.findVcsForPresentation}
/// @property presentCredentials - {@link OID4VPHolder.presentCredentials}
#[derive(uniffi::Object)]
pub struct OID4VPHolder {
    inner_holder: Box<dyn Holder>,
    #[cfg(debug_assertions)]
    in_mem_vault: InMemVault,
    #[cfg(debug_assertions)]
    local_kms: LocalKms,
}

#[uniffi::export(async_runtime = "tokio")]
impl OID4VPHolder {
    #[cfg(debug_assertions)]
    #[uniffi::constructor]
    pub async fn build_holder_for_test(client_id: String) -> Result<OID4VPHolder> {
        use agent_sdk::inmem::kms::LocalKms;
        use agent_sdk::inmem::vault::InMemVault;

        let kms = LocalKms::new();
        let vault = InMemVault::new();
        let builder =
            agent_sdk::vc::oid4vp::HolderBuilder::new(kms.clone(), vault.clone(), client_id)
                .with_http_client(
                    ReqwestClientBuilder::new()
                        .insecure()
                        .build()
                        .map_err(|e| Error::OID4VPHolder(e.to_string()))?,
                );

        let holder = builder
            .build()
            .await
            .map_err(|e| Error::OID4VPHolder(e.to_string()))?;

        Ok(OID4VPHolder {
            inner_holder: Box::new(holder),
            in_mem_vault: vault,
            local_kms: kms,
        })
    }

    #[cfg(debug_assertions)]
    pub async fn store_credential(
        &self,
        credential: Credential,
        metadata: JsonValue,
    ) -> Result<String> {
        let mut metadata = serde_json::from_value::<vc::CredentialMetadata>(metadata)
            .map_err(|err| Error::OID4VPHolder(format!("{:?}", err)))?;
        metadata.kid = self
            .local_kms
            .create(kms::KeyType::P256, Default::default())
            .await
            .map_err(|e| Error::OID4VPHolder(e.to_string()))?;

        self.in_mem_vault
            .store_credential(credential.try_into()?, &metadata)
            .await
            .map_err(|err| Error::OID4VPHolder(format!("{:?}", err)))
    }
    /// Fetches the `OID4VP` authorization request object from the provided URI.
    /// If the validation of authorization request fails then related `ProtocolError` response will be sent to the `response_uri` endpoint
    ///
    /// @param {string} requestUri - a request URI provided by the authorization URL.
    ///
    /// @returns {AuthorizationRequest} A {@link AuthorizationRequest} with the presentation definition and other relevant details on success.

    pub async fn get_authorization_request(
        &self,
        request_uri: String,
    ) -> Result<AuthorizationRequest> {
        self.inner_holder
            .get_authorization_request(
                &parse_url_arg(&request_uri).map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            )
            .await
            .map_err(|err| Error::OID4VPHolder(format!("{:?}", err)))
            .and_then(|result| result.try_into())
    }

    /// Automatically presents credentials to the Verifier based on the authorization request.
    ///
    /// This method selects the first appropriate credential that matches the requirements of the authorization request.
    /// To present specific credentials, use {@link OID4VPHolder.findVcsForPresentation} to discover suitable credentials and
    /// {@link OID4VPHolder.presentCredentials} to manually present them.
    ///
    /// @param {AuthorizationRequest} authRequest - the resolved authorization request containing the presentation requirements.
    /// @param {AuthorizationResponseMetadata} authResponseMetadata - the metadata for the authorization response.
    ///
    /// @returns {string | null}
    /// * A redirect URL if the presentation is successful
    /// * `null` on success without redirection.
    pub async fn present_credentials_auto(
        &self,
        auth_request: AuthorizationRequest,
        auth_response_metadata: AuthorizationResponseMetadata,
    ) -> Result<Option<String>> {
        let result = self
            .inner_holder
            .present_credentials_auto(
                &auth_request.try_into()?,
                &auth_response_metadata.try_into()?,
            )
            .await
            .map_err(|err| Error::OID4VPHolder(format!("{:?}", err)))?;

        Ok(result.map(|url: Url| url.to_string()))
    }

    /// Finds verifiable credentials required for the presentation based on the authorization request.
    ///
    /// @param {AuthorizationRequest} authRequest - the resolved authorization request containing the presentation requirements.
    ///
    /// @returns {Record<string, Array<CredentialEntry>}
    /// * An object of credentials that satisfy the authorization request's requirements.
    /// * If no matching credentials are found, an empty object is returned.
    pub async fn find_vcs_for_presentation(
        &self,
        auth_request: AuthorizationRequest,
    ) -> Result<HashMap<String, Vec<CredentialEntry>>> {
        let credentials_mapping = self
            .inner_holder
            .find_vcs_for_presentation(&auth_request.try_into()?)
            .await
            .map_err(|err| Error::OID4VPHolder(format!("{:?}", err)))?;

        convert_to_uniffi_credentials_mapping(credentials_mapping)
    }

    /// Manually presents credentials to the Verifier.
    ///
    /// @param {AuthorizationRequest} authRequest - the resolved authorization request.
    /// @param {Record<string, CredentialEntry>} credentialMapping - the map of credentials required for the presentation.
    /// @param {AuthorizationResponseMetadata} authResponseMetadata -the authorization response metadata.
    ///
    /// @returns {string | null}
    /// * A redirect URL if the presentation is successful
    /// * `null` on success without redirection.
    pub async fn present_credentials(
        &self,
        auth_request: AuthorizationRequest,
        credential_mapping: HashMap<String, CredentialEntry>,
        auth_response_metadata: AuthorizationResponseMetadata,
    ) -> Result<Option<String>> {
        let result = self
            .inner_holder
            .present_credentials(
                &auth_request.try_into()?,
                &convert_from_uniffi_credential_mapping(credential_mapping)?,
                &auth_response_metadata.try_into()?,
            )
            .await
            .map_err(|err| Error::OID4VPHolder(format!("{:?}", err)))?;

        Ok(result.map(|url: Url| url.to_string()))
    }

    /// Decline the authorization request by sending authorization error response to the `response_uri` endpoint.
    ///
    /// @param {AuthorizationRequest} authRequest - the resolved authorization request.
    pub async fn decline_authorization_request(
        &self,
        auth_request: AuthorizationRequest,
    ) -> Result<()> {
        let auth_request: ResolvedAuthRequest = auth_request.try_into()?;
        self.inner_holder
            .decline_authorization_request(&auth_request)
            .await
            .map_err(|err| Error::OID4VPHolder(err.to_string()))?;

        Ok(())
    }
}

#[derive(uniffi::Record)]
pub struct AuthorizationRequest {
    pub client_id: String,
    pub client_metadata: JsonValue,
    pub presentation_definition: JsonValue,
    pub nonce: String,
    pub response_type: String,
    pub response_mode: String,
    pub response_uri: String,
    pub state: Option<String>,
}

#[derive(uniffi::Record)]
pub struct JsIdTokenMetadata {
    pub key_metadata: KeyMetadata,
    pub lifetime: i64,
}

/// Metadata for an Authorization Response.
///
/// @property {Record<string, Array<string>> | null} [claimsToExclude] - map of claims divided by input descriptors that need to be excluded.
/// @property {IdTokenMetadata | null} [idTokenMetadata] - metadata containing the signing key and lifetime for the SIOP ID token
///
#[derive(uniffi::Record)]
pub struct AuthorizationResponseMetadata {
    pub claims_to_exclude: Option<HashMap<String, Vec<String>>>,
    pub id_token_metadata: Option<JsIdTokenMetadata>,
}

#[derive(uniffi::Record)]
pub struct KeyMetadata {
    pub did_url: String,
    pub kid: String,
}

#[derive(uniffi::Record)]
pub struct CredentialEntry {
    pub credential: Credential,
    pub kid: String,
    pub id: String,
}

#[derive(uniffi::Record)]
pub struct IdTokenMetadata {
    pub key_metadata: KeyMetadata,
    pub lifetime: i64,
}

#[derive(uniffi::Record)]
pub struct Credential {
    pub format: VCFormat,
    pub payload: String,
}

#[derive(uniffi::Enum)]
pub enum VCFormat {
    JwtVcJson,
    JwtVcJsonLD,
    LdpVc,
    SdJwtVc,
    MsoMdoc,
}

impl TryFrom<AuthorizationResponseMetadata> for oid4vp::AuthorizationResponseMetadata {
    type Error = Error;
    fn try_from(value: AuthorizationResponseMetadata) -> Result<Self> {
        Ok(Self {
            claims_to_exclude: value.claims_to_exclude,
            id_token_metadata: value.id_token_metadata.map(|idt| oid4vp::IdTokenMetadata {
                key_metadata: vc::core::KeyMetadata {
                    did_url: idt.key_metadata.did_url,
                    kid: idt.key_metadata.kid,
                },
                lifetime: time::Duration::new(idt.lifetime, 0),
            }),
        })
    }
}

impl TryFrom<AuthorizationRequest> for ResolvedAuthRequest {
    type Error = Error;

    fn try_from(value: AuthorizationRequest) -> Result<Self> {
        Ok(ResolvedAuthRequest {
            client_id: value.client_id,
            client_metadata: serde_json::from_value(value.client_metadata)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            presentation_definition: serde_json::from_value(value.presentation_definition)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            nonce: serde_json::from_value(serde_json::Value::String(value.nonce))
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            response_type: value.response_type.into(),
            response_mode: value.response_mode.into(),
            response_uri: parse_url_arg(&value.response_uri)
                .map_err(|err| Error::OID4VPHolder(format!("{err:?}")))?,
            state: value.state,
        })
    }
}

impl TryFrom<ResolvedAuthRequest> for AuthorizationRequest {
    type Error = Error;

    fn try_from(value: ResolvedAuthRequest) -> Result<Self> {
        Ok(AuthorizationRequest {
            client_id: value.client_id,
            client_metadata: serde_json::to_value(&value.client_metadata)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            presentation_definition: serde_json::to_value(&value.presentation_definition)
                .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            nonce: value.nonce.secret().to_string(),
            response_type: value.response_type.into(),
            response_mode: value.response_mode.into(),
            response_uri: value.response_uri.to_string(),
            state: value.state,
        })
    }
}
impl TryFrom<agent_sdk::vault::CredentialEntry> for CredentialEntry {
    type Error = Error;

    fn try_from(value: agent_sdk::vault::CredentialEntry) -> Result<Self> {
        Ok(CredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
            id: value.id,
        })
    }
}

impl TryFrom<CredentialEntry> for agent_sdk::vault::CredentialEntry {
    type Error = Error;

    fn try_from(value: CredentialEntry) -> Result<Self> {
        Ok(agent_sdk::vault::CredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
            id: value.id,
        })
    }
}

impl TryFrom<agent_sdk::vc::Credential> for Credential {
    type Error = Error;

    fn try_from(value: agent_sdk::vc::Credential) -> Result<Self> {
        let result = match value {
            agent_sdk::vc::Credential::JwtVcJson(payload) => Self {
                format: VCFormat::JwtVcJson,
                payload,
            },
            agent_sdk::vc::Credential::JwtVcJsonLd(payload) => Self {
                format: VCFormat::JwtVcJsonLD,
                payload,
            },
            agent_sdk::vc::Credential::LdpVc(payload) => Self {
                format: VCFormat::LdpVc,
                payload: serde_json::to_string(&payload)
                    .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            },
            agent_sdk::vc::Credential::SdJwt(payload) => Self {
                format: VCFormat::SdJwtVc,
                payload,
            },
            _ => {
                return Err(Error::OID4VPHolder(format!(
                    "Unsupported credential format {}",
                    value.format()
                )))
            }
        };

        Ok(result)
    }
}

impl TryFrom<Credential> for agent_sdk::vc::Credential {
    type Error = Error;

    fn try_from(value: Credential) -> Result<Self> {
        let result = match value.format {
            VCFormat::JwtVcJson => Self::JwtVcJson(value.payload),
            VCFormat::JwtVcJsonLD => Self::JwtVcJsonLd(value.payload),
            VCFormat::LdpVc => Self::LdpVc(
                serde_json::from_str(&value.payload)
                    .map_err(|e| Error::OID4VPHolder(format!("{e:?}")))?,
            ),
            VCFormat::SdJwtVc => Self::SdJwt(value.payload),
            VCFormat::MsoMdoc => {
                return Err(Error::OID4VPHolder(
                    "Unsupported credential format: MSO MDOC".to_string(),
                ))
            }
        };

        Ok(result)
    }
}

fn convert_to_uniffi_credentials_mapping(
    input: CredentialsMapping,
) -> Result<HashMap<String, Vec<CredentialEntry>>> {
    input
        .into_iter()
        .map(|(key, vec)| {
            let converted_vec: Result<Vec<CredentialEntry>> =
                vec.into_iter().map(|entry| entry.try_into()).collect();
            converted_vec.map(|vec| (key, vec))
        })
        .collect()
}

fn convert_from_uniffi_credential_mapping(
    input: HashMap<String, CredentialEntry>,
) -> Result<CredentialMapping> {
    input
        .into_iter()
        .map(|(key, val)| {
            let converted_val: Result<agent_sdk::vault::CredentialEntry> = val.try_into();
            converted_val.map(|v| (key, v))
        })
        .collect()
}
