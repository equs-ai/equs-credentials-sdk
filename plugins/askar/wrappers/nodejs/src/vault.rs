use crate::kms::Alg;
use crate::AskarStorage;
use askar::vault::{Credential, CredentialEntry, CredentialMetadata, HasVCFormat, VCFormat, Vault};
use napi::{Error, Result};
use napi_derive::napi;
use serde::{Deserialize, Serialize};

#[napi]
pub struct AskarVault(askar::vault::AskarVault);

#[napi]
impl AskarVault {
    #[napi(constructor)]
    pub fn new(storage: &AskarStorage) -> Self {
        let storage = storage.clone();
        let vault = askar::vault::AskarVault::new(storage.0.clone());

        AskarVault(vault)
    }

    #[allow(private_interfaces)]
    #[napi]
    pub async fn store_credential(
        &self,
        #[napi(ts_arg_type = "Credential")] credential: InnerCredential,
        #[napi(ts_arg_type = "CredentialMetadata")] metadata: InnerCredentialMetadata,
    ) -> Result<String> {
        self.0
            .store_credential(credential.try_into()?, &metadata.into())
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[allow(private_interfaces)]
    #[napi(ts_return_type = "Promise<CredentialEntry | null>")]
    pub async fn get_credential(&self, id: String) -> Result<Option<InnerCredentialEntry>> {
        let credential = self
            .0
            .get_credential(&id)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        credential.map(|entry| entry.try_into()).transpose()
    }

    #[allow(private_interfaces)]
    #[napi(ts_return_type = "Promise<Array<CredentialEntry>>")]
    pub async fn get_credentials(&self) -> Result<Vec<InnerCredentialEntry>> {
        let credentials = self
            .0
            .get_credentials()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        credentials
            .into_iter()
            .map(|entry| entry.try_into())
            .collect()
    }

    #[napi]
    pub async fn delete_credential(&self, id: String) -> Result<()> {
        self.0
            .delete_credential(&id)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))
    }

    #[allow(private_interfaces)]
    #[napi(ts_return_type = "Promise<Array<CredentialEntry>>")]
    pub async fn find_credentials(&self, fields: Vec<String>) -> Result<Vec<InnerCredentialEntry>> {
        let credentials = self
            .0
            .find_credentials(fields)
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        credentials
            .into_iter()
            .map(|entry| entry.try_into())
            .collect()
    }

    #[allow(clippy::missing_safety_doc)]
    #[napi]
    pub async unsafe fn close_vault(&mut self) -> Result<()> {
        self.0
            .to_owned()
            .close_vault()
            .await
            .map_err(|e| Error::from_reason(e.to_string()))?;

        Ok(())
    }
}

#[napi]
#[derive(Debug, Serialize, Deserialize)]
pub enum InnerVCFormat {
    JwtVcJson,
    JwtVcJsonLD,
    LdpVc,
    SdJwtVc,
    MsoMdoc,
}

impl From<InnerVCFormat> for VCFormat {
    fn from(value: InnerVCFormat) -> Self {
        match value {
            InnerVCFormat::JwtVcJson => VCFormat::JwtVcJson,
            InnerVCFormat::JwtVcJsonLD => VCFormat::JwtVcJsonLD,
            InnerVCFormat::LdpVc => VCFormat::LdpVc,
            InnerVCFormat::SdJwtVc => VCFormat::SdJwtVc,
            InnerVCFormat::MsoMdoc => VCFormat::MsoMdoc,
        }
    }
}

#[napi(object)]
#[derive(Debug, Serialize, Deserialize)]
struct InnerCredential {
    pub format: InnerVCFormat,
    pub payload: String,
}

impl TryFrom<InnerCredential> for Credential {
    type Error = Error;

    fn try_from(value: InnerCredential) -> Result<Self> {
        let result = match value.format {
            InnerVCFormat::JwtVcJson => Self::JwtVcJson(value.payload),
            InnerVCFormat::JwtVcJsonLD => Self::JwtVcJsonLd(value.payload),
            InnerVCFormat::LdpVc => Self::LdpVc(serde_json::from_str(&value.payload)?),
            InnerVCFormat::SdJwtVc => Self::SdJwt(value.payload),
            _ => {
                return Err(Error::from_reason(
                    "Unsupported credential format: MSO MDOC",
                ))
            }
        };

        Ok(result)
    }
}

impl TryFrom<Credential> for InnerCredential {
    type Error = Error;

    fn try_from(value: Credential) -> Result<Self> {
        let result = match value {
            Credential::JwtVcJson(payload) => Self {
                format: InnerVCFormat::JwtVcJson,
                payload,
            },
            Credential::JwtVcJsonLd(payload) => Self {
                format: InnerVCFormat::JwtVcJsonLD,
                payload,
            },
            Credential::LdpVc(payload) => Self {
                format: InnerVCFormat::LdpVc,
                payload: serde_json::to_string(&payload)?,
            },
            Credential::SdJwt(payload) => Self {
                format: InnerVCFormat::SdJwtVc,
                payload,
            },
            _ => {
                return Err(Error::from_reason(format!(
                    "Unsupported credential format {}",
                    value.format()
                )))
            }
        };

        Ok(result)
    }
}
#[napi(object)]
struct InnerCredentialMetadata {
    pub type_: String,
    pub format: InnerVCFormat,
    pub kid: String,
    pub alg: Option<Alg>,
    pub fields: Vec<String>,
}

impl From<InnerCredentialMetadata> for CredentialMetadata {
    fn from(value: InnerCredentialMetadata) -> Self {
        Self {
            type_: value.type_,
            format: value.format.into(),
            kid: value.kid,
            alg: value.alg.map(|value| value.into()),
            fields: value.fields,
        }
    }
}

#[napi(object)]
struct InnerCredentialEntry {
    pub credential: InnerCredential,
    pub kid: String,
    pub id: String,
}

impl TryFrom<CredentialEntry> for InnerCredentialEntry {
    type Error = Error;

    fn try_from(value: CredentialEntry) -> Result<Self> {
        Ok(InnerCredentialEntry {
            credential: value.credential.try_into()?,
            kid: value.kid,
            id: value.id,
        })
    }
}
