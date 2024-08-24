use async_trait::async_trait;

use crate::vc;

// Error handling
#[derive(Debug, thiserror::Error, strum::IntoStaticStr)]
#[non_exhaustive]
pub enum Error {
    // TODO: change `get_credential` to return Option<Credential> in result?
    #[error("credential not found for ID: {0}")]
    NotFound(String),
    #[error("Storage error: {0}")]
    Storage(String),
    #[error("Format not supported: {0}")]
    FormatNotSupported(String),
    #[error("VC error: {0}")]
    VC(String),
    #[error("Network error: {0}")]
    Network(String),
    #[error("Invalid criteria: {0}")]
    FindCriteria(String),
}

#[non_exhaustive]
pub enum FindCriteria {
    ByTypeAndFormat(String, String),
    // etc
}

#[async_trait]
pub trait Vault: Send + Sync
{
    async fn store_credential(&self, credential: vc::Credential, metadata: &vc::CredentialMetadata) -> Result<String, Error>;

    async fn get_credential(&self, id: &str) -> Result<vc::Credential, Error>;

    async fn find_credentials(&self, criteria: FindCriteria) -> Result<Vec<vc::Credential>, Error>;
}

#[cfg(test)]
pub mod test_util {
    use crate::vault::{FindCriteria, Vault};
    use crate::vc::{Credential, CredentialMetadata, VCFormat};

    pub async fn test_vault<V: Vault>(vault: V) {
        // test data
        let cred1 = "token".to_string();
        let cred1_meta = CredentialMetadata {
            type_: "https://credentials.example.com/identity_credential".into(),
            format: VCFormat::SdJwtVc,
            alg: None,
            tags: vec![],
        };
        let cred2str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let cred2: ssi::vc::Credential = serde_json::from_str(cred2str).unwrap();
        let cred2_meta = CredentialMetadata {
            type_: "VerifiableCredential".into(),
            format: VCFormat::LdpVc,
            alg: None,
            tags: vec![],
        };

        let cred1_id = vault
            .store_credential(Credential::SdJwt(cred1.clone()), &cred1_meta)
            .await
            .unwrap();
        let cred2_id = vault
            .store_credential(Credential::LdpVc(cred2.clone()), &cred2_meta)
            .await
            .unwrap();

        let get1_res = vault.get_credential(&cred1_id).await.unwrap();
        let get2_res = vault.get_credential(&cred2_id).await.unwrap();

        assert_eq!(get1_res, Credential::SdJwt(cred1.clone()));
        assert_eq!(get2_res, Credential::LdpVc(cred2));

        let find_res = vault
            .find_credentials(FindCriteria::ByTypeAndFormat(
                "https://credentials.example.com/identity_credential".to_owned(),
                VCFormat::SdJwtVc.to_string(),
            ))
            .await
            .unwrap();

        assert_eq!(find_res, vec![Credential::SdJwt(cred1)]);
    }
}