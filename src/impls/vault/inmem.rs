use std::collections::HashMap;

use async_trait::async_trait;
use futures::future;

use crate::core_;
use crate::core_::storage::Storage;
use crate::core_::vault::{Error, FindCriteria};
use crate::core_::vc;
use crate::core_::vc::{Credential, CredentialMetadata};
use crate::impls::storage::inmem::InMemStorage;

pub struct InMemVault {
    storage: InMemStorage<String, Credential>,
    indexed: HashMap<String, Vec<String>>,
}

impl InMemVault {
    pub fn for_store(storage: InMemStorage<String, Credential>) -> Self {
        Self { storage, indexed: HashMap::new() }
    }

    pub fn new() -> Self {
        Self { storage: InMemStorage::new(), indexed: HashMap::new() }
    }


    fn update_index(&mut self, metadata: &CredentialMetadata, storage_id: &str) -> Result<(), Error> {
        let index = format!("{}:{}", metadata.id, metadata.format);

        if !self.indexed.contains_key(&index) {
            self.indexed.insert(index.clone(), vec![]);
        }

        self.indexed.get_mut(&index).unwrap().push(storage_id.to_owned());

        Ok(())
    }

    fn get_indexed(&self, id: &str, format: vc::VCFormat) -> Vec<String> {
        let index = format!("{}:{}", id, format);
        let vec = self.indexed.get(&index);
        if vec.is_none() { return Vec::new(); }
        vec.unwrap().to_owned()
    }
}

#[async_trait]
impl core_::vault::Vault for InMemVault {
    fn open(&self, master_secret: &str) -> Result<(), Error> {
        Ok(())
    }

    fn close(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn store_credential(&mut self, credential: Credential, metadata: &CredentialMetadata) -> Result<String, Error> {
        let storage_id = random_string::generate(5, random_string::charsets::ALPHA);

        let _ = self.storage.put(storage_id.clone(), credential.clone()).await?;
        self.update_index(metadata, &storage_id)?;
        Ok(storage_id)
    }

    async fn get_credential(&self, id: &String) -> Result<&Credential, Error> {
        let cred = self.storage.get(id).await.unwrap();
        Ok(cred)
    }

    async fn find_credentials(&self, criteria: FindCriteria) -> Result<Vec<&Credential>, Error> {
        let creds = match criteria {
            FindCriteria::ByIdAndFormat(id, fmt) => {
                let ids = self.get_indexed(&id, fmt);
                let creds = future::try_join_all(ids.iter().map(|id| self.get_credential(id)))
                    .await?;
                creds
            }
        };

        Ok(creds)
    }
}


#[cfg(test)]
mod tests {
    use crate::core_::crypto::Alg;
    use crate::core_::vault::{FindCriteria, Vault};
    use crate::core_::vc;
    use crate::core_::vc::{Credential, CredentialMetadata, VCFormat};
    use crate::impls::storage::inmem::InMemStorage;
    use crate::impls::vault::inmem::InMemVault;

    #[tokio::test]
    async fn e2e() {
        // init
        let secret = "abracadabra".to_string();
        let storage = InMemStorage::new();
        let mut vault = InMemVault::for_store(storage);

        // test data
        let cred1 = "token".to_string();
        let cred1_meta = CredentialMetadata { id: "id1".into(), format: VCFormat::SdJwtVc, alg: Alg::ES256 };
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
        let cred2: vc::ldp_vc::Credential = serde_json::from_str(cred2str).unwrap();
        let cred2_meta = CredentialMetadata { id: "id2".into(), format: VCFormat::LdpVc, alg: Alg::ES256 };

        let store1_res = vault.store_credential(Credential::SdJwt(cred1.clone()), &cred1_meta).await;
        assert!(store1_res.is_ok());
        let store2_res = vault.store_credential(Credential::LdpVc(cred2.clone()), &cred2_meta).await;
        assert!(store2_res.is_ok());

        let cred1_id = store1_res.unwrap();
        let cred2_id = store2_res.unwrap();

        let get1_res = vault.get_credential(&cred1_id).await;
        assert!(get1_res.is_ok());
        let get2_res = vault.get_credential(&cred2_id).await;
        assert!(get2_res.is_ok());

        assert_eq!(get1_res.unwrap(), &Credential::SdJwt(cred1.clone()));
        assert_eq!(get2_res.unwrap(), &Credential::LdpVc(cred2));

        let find_res = vault.find_credentials(FindCriteria::ByIdAndFormat("id1".to_owned(), VCFormat::SdJwtVc)).await;
        assert!(find_res.is_ok());

        assert_eq!(find_res.unwrap(), vec![&Credential::SdJwt(cred1)]);
    }
}