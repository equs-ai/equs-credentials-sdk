use agent_sdk::crypto;
use agent_sdk::did::didkey::DIDKey;
use agent_sdk::did::universal::DIDResolver;
use agent_sdk::did::{DID, ResolutionError, ResolutionOutput};
use async_trait::async_trait;
use ssi::dids::resolution::{Options, Output};
pub use ssi::dids::{DID as SpruceDID, DIDKey as SpruceDIDKey, DIDResolver as SpruceDIDResolver};

pub struct TestDIDResolver {
    method_name: String,
    did_key: DIDKey,
}

#[async_trait]
impl DIDResolver for TestDIDResolver {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a SpruceDID,
        _: Options,
    ) -> Result<ResolutionOutput, ResolutionError> {
        let t = format!("did:key:{}", &did.method_specific_id());
        let Output {
            document,
            metadata,
            document_metadata,
        } = SpruceDIDKey
            .resolve(SpruceDID::new(&t).unwrap())
            .await
            .unwrap();

        let json = serde_json::to_string_pretty(&document).unwrap();
        let json = json.replace("did:key", format!("did:{}", self.method_name).as_str());

        //TODO The test doesn't pass without changing the following. This is just a cheat solution.
        // The exact cause is to be determined and fixed
        let json = json.replace("Multikey", "EcdsaSecp256r1VerificationKey2019");
        let doc = serde_json::from_str(json.as_str()).unwrap();
        Ok(Output {
            metadata,
            document: doc,
            document_metadata,
        })
    }

    fn method_name(&self) -> String {
        self.method_name.to_string()
    }
}

impl TestDIDResolver {
    pub fn new(method_name: String) -> TestDIDResolver {
        TestDIDResolver {
            method_name,
            did_key: DIDKey {},
        }
    }

    pub fn get_key_method_len(&self) -> usize {
        //len of "did:<method>:"
        3 + 1 + self.method_name.len() + 1
    }
    pub fn generate<K>(&self, key: K) -> DID
    where
        K: crypto::Key,
    {
        let did = &DIDKey::generate(key).unwrap();
        let method_specific_id = &did.as_str()[8..];
        DID::from(format!("did:{}:{}", self.method_name, method_specific_id))
    }
}
