use crate::core_;
use crate::core_::storage::Storage;
use crate::core_::vault::{Error, FindCriteria};
use crate::core_::vc::Credential;
use crate::impls::storage::inmem::InMemStorage;

pub struct InMemVault {
    storage: InMemStorage<String, Credential>,
}

impl InMemVault {
    pub fn for_store(storage: InMemStorage<String, Credential>) -> Self {
        Self { storage }
    }

    pub fn new() -> Self {
        Self { storage: InMemStorage::new() }
    }
}

impl core_::vault::Vault for InMemVault {
    fn open(&self, master_secret: &str) -> Result<(), Error> {
        Ok(())
    }

    fn close(&self) -> Result<(), Error> {
        Ok(())
    }

    async fn store_credential(&mut self, credential: Credential) -> Result<String, Error> {
        let id = random_string::generate(10, random_string::charsets::ALPHA);

        let _ = self.storage.put(id.clone(), credential).await;
        Ok(id)
    }

    async fn get_credential(&self, id: &String) -> Result<&Credential, Error> {
        let cred = self.storage.get(id).await.unwrap();
        Ok(cred)
    }

    async fn find_credentials(&self, criteria: FindCriteria) -> Result<Vec<Credential>, Error> {
        unimplemented!()
    }
}


#[cfg(test)]
mod tests {
    use crate::core_::vault::Vault;
    use crate::core_::vc;
    use crate::core_::vc::Credential;
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

        let store1_res = vault.store_credential(Credential::SdJwt(cred1.clone())).await;
        assert!(store1_res.is_ok());
        let store2_res = vault.store_credential(Credential::LdpVc(cred2.clone())).await;
        assert!(store2_res.is_ok());

        let cred1_id = store1_res.unwrap();
        let cred2_id = store2_res.unwrap();

        let get1_res = vault.get_credential(&cred1_id).await;
        assert!(get1_res.is_ok());
        let get2_res = vault.get_credential(&cred2_id).await;
        assert!(get2_res.is_ok());

        assert_eq!(get1_res.unwrap(), &Credential::SdJwt(cred1));
        assert_eq!(get2_res.unwrap(), &Credential::LdpVc(cred2));
    }
}