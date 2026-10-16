use std::collections::BTreeMap;

use iref::IriBuf;
use serde_json::Value;
use ssi::OneOrMany;
use ssi::dids::document::DIDVerificationMethod;
use ssi::dids::{DIDBuf, DIDURLBuf, Document};

use crate::did::ResolutionError;
use crate::did::didethr::types::{Address, VerificationKeyType};

#[derive(Clone, Debug, PartialEq)]
struct StoredVerificationMethod {
    key: String,
    id: String,
    type_: VerificationKeyType,
    controller: String,
    blockchain_account_id: Option<String>,
    public_key_multibase: Option<String>,
    public_key_hex: Option<String>,
    public_key_base58: Option<String>,
    public_key_base64: Option<String>,
    public_key_jwk: Option<String>,
}

#[derive(Clone, Debug, PartialEq)]
struct StoredReference {
    key: String,
    reference: String,
}

#[derive(Clone, Debug, PartialEq)]
struct StoredService {
    key: String,
    id: String,
    type_: String,
    service_endpoint: String,
}

#[derive(Clone, Debug, Default, PartialEq)]
pub struct DidDocumentBuilder {
    id: String,
    controller: Option<String>,
    verification_method: Vec<StoredVerificationMethod>,
    authentication: Vec<StoredReference>,
    assertion_method: Vec<StoredReference>,
    capability_invocation: Vec<StoredReference>,
    capability_delegation: Vec<StoredReference>,
    key_agreement: Vec<StoredReference>,
    service: Vec<StoredService>,
    also_known_as: Option<Vec<String>>,
    deactivated: bool,
    key_index: u32,
    service_index: u32,
}

impl DidDocumentBuilder {
    pub fn new() -> DidDocumentBuilder {
        DidDocumentBuilder::default()
    }

    pub fn base_for_did(did: &str, chain_id: u64) -> Result<DidDocumentBuilder, ResolutionError> {
        let identity = Address::from(did);
        let kid = "controller";
        let id_str = format!("{}#controller", did);

        let mut builder = DidDocumentBuilder::new();
        builder.set_id(did);

        builder.add_verification_method(
            kid,
            &id_str,
            &VerificationKeyType::EcdsaSecp256k1RecoveryMethod2020,
            Some(identity.as_blockchain_id(chain_id).as_str()),
            None,
            None,
            None,
            None,
            None,
        );
        builder.add_authentication_reference(kid)?;
        builder.add_assertion_method_reference(kid)?;
        Ok(builder)
    }

    pub fn set_id(&mut self, id: &str) {
        self.id = id.to_owned();
    }

    pub fn get_id(&self) -> String {
        self.id.to_owned()
    }

    pub fn set_controller(&mut self, controller: &str) {
        self.controller = Some(controller.to_string());
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_verification_method(
        &mut self,
        key: &str,
        id: &str,
        type_: &VerificationKeyType,
        blockchain_account_id: Option<&str>,
        public_key_multibase: Option<&str>,
        public_key_hex: Option<&str>,
        public_key_base58: Option<&str>,
        public_key_base64: Option<&str>,
        public_key_jwk: Option<&str>,
    ) {
        let vm = StoredVerificationMethod {
            key: key.to_string(),
            id: id.to_string(),
            type_: type_.clone(),
            controller: self.id.clone(),
            blockchain_account_id: blockchain_account_id.map(|s| s.to_string()),
            public_key_multibase: public_key_multibase.map(|s| s.to_string()),
            public_key_hex: public_key_hex.map(|s| s.to_string()),
            public_key_base58: public_key_base58.map(|s| s.to_string()),
            public_key_base64: public_key_base64.map(|s| s.to_string()),
            public_key_jwk: public_key_jwk.map(|s| s.to_string()),
        };

        self.verification_method.push(vm);
    }

    #[allow(clippy::too_many_arguments)]
    pub fn add_delegate_key(
        &mut self,
        key: &str,
        type_: &VerificationKeyType,
        blockchain_account_id: Option<&str>,
        public_key_multibase: Option<&str>,
        public_key_hex: Option<&str>,
        public_key_base58: Option<&str>,
        public_key_base64: Option<&str>,
        public_key_jwk: Option<&str>,
    ) {
        self.key_index += 1;
        let id_str = format!("{}#delegate-{}", self.id, self.key_index);

        self.add_verification_method(
            key,
            &id_str,
            type_,
            blockchain_account_id,
            public_key_multibase,
            public_key_hex,
            public_key_base58,
            public_key_base64,
            public_key_jwk,
        );
    }

    pub fn remove_delegate_key(&mut self, key: &str) -> Result<(), ResolutionError> {
        self.verification_method.retain(|vm| vm.key != key);
        Ok(())
    }

    pub fn add_authentication_reference(&mut self, key: &str) -> Result<(), ResolutionError> {
        let vm = self
            .verification_method
            .iter()
            .find(|vm| vm.key == key)
            .ok_or_else(|| {
                ResolutionError::Internal("Verification method not found".to_string())
            })?;

        self.authentication.push(StoredReference {
            key: key.to_string(),
            reference: vm.id.clone(),
        });

        Ok(())
    }

    pub fn remove_authentication_reference(&mut self, key: &str) -> Result<(), ResolutionError> {
        self.authentication.retain(|r| r.key != key);
        Ok(())
    }

    pub fn add_assertion_method_reference(&mut self, key: &str) -> Result<(), ResolutionError> {
        let vm = self
            .verification_method
            .iter()
            .find(|vm| vm.key == key)
            .ok_or_else(|| {
                ResolutionError::Internal("Verification method not found".to_string())
            })?;

        self.assertion_method.push(StoredReference {
            key: key.to_string(),
            reference: vm.id.clone(),
        });

        Ok(())
    }

    pub fn remove_assertion_method_reference(&mut self, key: &str) -> Result<(), ResolutionError> {
        self.assertion_method.retain(|r| r.key != key);
        Ok(())
    }

    pub fn add_key_agreement_reference(&mut self, key: &str) -> Result<(), ResolutionError> {
        let vm = self
            .verification_method
            .iter()
            .find(|vm| vm.key == key)
            .ok_or_else(|| {
                ResolutionError::Internal("Verification method not found".to_string())
            })?;

        self.key_agreement.push(StoredReference {
            key: key.to_string(),
            reference: vm.id.clone(),
        });

        Ok(())
    }

    pub fn remove_key_agreement_reference(&mut self, key: &str) -> Result<(), ResolutionError> {
        self.key_agreement.retain(|r| r.key != key);
        Ok(())
    }

    pub fn add_capability_invocation_reference(
        &mut self,
        key: &str,
    ) -> Result<(), ResolutionError> {
        let vm = self
            .verification_method
            .iter()
            .find(|vm| vm.key == key)
            .ok_or_else(|| {
                ResolutionError::Internal("Verification method not found".to_string())
            })?;

        self.capability_invocation.push(StoredReference {
            key: key.to_string(),
            reference: vm.id.clone(),
        });

        Ok(())
    }

    pub fn remove_capability_invocation_reference(
        &mut self,
        key: &str,
    ) -> Result<(), ResolutionError> {
        self.capability_invocation.retain(|r| r.key != key);
        Ok(())
    }

    pub fn add_capability_delegation_reference(
        &mut self,
        key: &str,
    ) -> Result<(), ResolutionError> {
        let vm = self
            .verification_method
            .iter()
            .find(|vm| vm.key == key)
            .ok_or_else(|| {
                ResolutionError::Internal("Verification method not found".to_string())
            })?;

        self.capability_delegation.push(StoredReference {
            key: key.to_string(),
            reference: vm.id.clone(),
        });

        Ok(())
    }

    pub fn remove_capability_delegation_reference(
        &mut self,
        key: &str,
    ) -> Result<(), ResolutionError> {
        self.capability_delegation.retain(|r| r.key != key);
        Ok(())
    }

    pub fn add_service(
        &mut self,
        key: &str,
        id: Option<&str>,
        type_: &str,
        service_endpoint: &str,
    ) {
        self.service_index += 1;

        let id_str = id
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("{}#service-{}", self.id, self.service_index));

        self.service.push(StoredService {
            key: key.to_string(),
            id: id_str,
            type_: type_.to_string(),
            service_endpoint: service_endpoint.to_string(),
        });
    }

    pub fn remove_service(&mut self, key: &str) -> Result<(), ResolutionError> {
        self.service.retain(|s| s.key != key);
        Ok(())
    }

    pub fn set_also_known_as(&mut self, values: Vec<String>) {
        self.also_known_as = Some(values);
    }

    pub fn deactivate(&mut self) {
        self.deactivated = true;
    }

    pub fn deactivated(&self) -> bool {
        self.deactivated
    }

    pub fn build(self) -> Result<Document, ResolutionError> {
        let DidDocumentBuilder {
            id,
            controller,
            verification_method,
            authentication,
            assertion_method,
            capability_invocation,
            capability_delegation,
            key_agreement,
            service: _service,
            also_known_as,
            deactivated: _deactivated,
            key_index: _,
            service_index: _,
        } = self;

        let did = DIDBuf::from_string(id.clone())
            .map_err(|e| ResolutionError::Internal(format!("Invalid DID `{}`: {e}", id)))?;

        let mut doc = Document::new(did);

        doc.also_known_as = also_known_as
            .unwrap_or_default()
            .into_iter()
            .map(|s| {
                IriBuf::new(s)
                    .map_err(|e| ResolutionError::Internal(format!("Invalid alsoKnownAs IRI: {e}")))
            })
            .collect::<Result<Vec<_>, ResolutionError>>()?;

        if let Some(controller) = controller {
            let controller_did = DIDBuf::from_string(controller)
                .map_err(|e| ResolutionError::Internal(format!("Invalid controller DID: {e}")))?;
            doc.controller = Some(OneOrMany::One(controller_did));
        }

        doc.verification_method = verification_method
            .into_iter()
            .map(Self::to_ssi_verification_method)
            .collect::<Result<Vec<_>, ResolutionError>>()?;

        doc.verification_relationships.authentication = authentication
            .into_iter()
            .map(|r| Self::to_ssi_reference(r.reference, "authentication"))
            .collect::<Result<_, ResolutionError>>()?;

        doc.verification_relationships.assertion_method = assertion_method
            .into_iter()
            .map(|r| Self::to_ssi_reference(r.reference, "assertionMethod"))
            .collect::<Result<_, ResolutionError>>()?;

        doc.verification_relationships.key_agreement = key_agreement
            .into_iter()
            .map(|r| Self::to_ssi_reference(r.reference, "keyAgreement"))
            .collect::<Result<_, ResolutionError>>()?;

        doc.verification_relationships.capability_invocation = capability_invocation
            .into_iter()
            .map(|r| Self::to_ssi_reference(r.reference, "capabilityInvocation"))
            .collect::<Result<_, ResolutionError>>()?;

        doc.verification_relationships.capability_delegation = capability_delegation
            .into_iter()
            .map(|r| Self::to_ssi_reference(r.reference, "capabilityDelegation"))
            .collect::<Result<_, ResolutionError>>()?;

        doc.service = Vec::new();

        let mut property_set = BTreeMap::new();
        property_set.insert(
            "@context".to_string(),
            Value::Array(vec![
                Value::String("https://www.w3.org/ns/did/v1".to_string()),
                Value::Object({
                    let mut ctx = serde_json::Map::new();
                    ctx.insert(
                        "EcdsaSecp256k1RecoveryMethod2020".to_string(),
                        Value::String(
                            "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020"
                                .to_string(),
                        ),
                    );
                    ctx.insert(
                        "EcdsaSecp256k1VerificationKey2019".to_string(),
                        Value::String(
                            "https://w3id.org/security#EcdsaSecp256k1VerificationKey2019"
                                .to_string(),
                        ),
                    );
                    ctx.insert(
                        "Ed25519VerificationKey2018".to_string(),
                        Value::String(
                            "https://w3id.org/security#Ed25519VerificationKey2018"
                                .to_string(),
                        ),
                    );
                    ctx.insert(
                        "blockchainAccountId".to_string(),
                        Value::String("https://w3id.org/security#blockchainAccountId".to_string()),
                    );
                    ctx.insert(
                        "publicKeyMultibase".to_string(),
                        Value::String("https://w3id.org/security#publicKeyMultibase".to_string()),
                    );
                    ctx.insert(
                        "publicKeyHex".to_string(),
                        Value::String("https://w3id.org/security#publicKeyHex".to_string()),
                    );
                    ctx.insert(
                        "publicKeyBase58".to_string(),
                        Value::String("https://w3id.org/security#publicKeyBase58".to_string()),
                    );
                    ctx.insert(
                        "publicKeyBase64".to_string(),
                        Value::String("https://w3id.org/security#publicKeyBase64".to_string()),
                    );
                    ctx.insert(
                        "publicKeyJwk".to_string(),
                        Value::String("https://w3id.org/security#publicKeyJwk".to_string()),
                    );
                    ctx
                }),
            ]),
        );
        doc.property_set = property_set;

        Ok(doc)
    }

    fn to_ssi_reference(
        value: String,
        field_name: &str,
    ) -> Result<ssi::dids::document::verification_method::ValueOrReference, ResolutionError> {
        DIDURLBuf::from_string(value)
            .map(|u| u.into())
            .map_err(|e| ResolutionError::Internal(format!("Invalid {field_name} reference: {e}")))
    }

    fn to_ssi_verification_method(
        vm: StoredVerificationMethod,
    ) -> Result<DIDVerificationMethod, ResolutionError> {
        let controller = DIDBuf::from_string(vm.controller.clone()).map_err(|e| {
            ResolutionError::Internal(format!(
                "Invalid verification method controller `{}`: {e}",
                vm.controller
            ))
        })?;

        let id = DIDURLBuf::from_string(vm.id.clone()).map_err(|e| {
            ResolutionError::Internal(format!("Invalid verification method id `{}`: {e}", vm.id))
        })?;

        let mut properties = BTreeMap::new();

        if let Some(v) = vm.blockchain_account_id {
            properties.insert("blockchainAccountId".to_string(), Value::String(v));
        }
        if let Some(v) = vm.public_key_multibase {
            properties.insert("publicKeyMultibase".to_string(), Value::String(v));
        }
        if let Some(v) = vm.public_key_hex {
            properties.insert("publicKeyHex".to_string(), Value::String(v));
        }
        if let Some(v) = vm.public_key_base58 {
            properties.insert("publicKeyBase58".to_string(), Value::String(v));
        }
        if let Some(v) = vm.public_key_base64 {
            properties.insert("publicKeyBase64".to_string(), Value::String(v));
        }
        if let Some(v) = vm.public_key_jwk {
            let jwk_json: Value = serde_json::from_str(&v).map_err(|e| {
                ResolutionError::Internal(format!("Invalid publicKeyJwk JSON: {e}"))
            })?;
            properties.insert("publicKeyJwk".to_string(), jwk_json);
        }

        Ok(DIDVerificationMethod {
            id,
            type_: Self::verification_key_type_to_ssi(&vm.type_),
            controller,
            properties,
        })
    }

    fn verification_key_type_to_ssi(type_: &VerificationKeyType) -> String {
        match type_ {
            VerificationKeyType::EcdsaSecp256k1RecoveryMethod2020 => {
                "EcdsaSecp256k1RecoveryMethod2020".to_string()
            }
            VerificationKeyType::EcdsaSecp256k1VerificationKey2019 => {
                "EcdsaSecp256k1VerificationKey2019".to_string()
            }
            VerificationKeyType::Ed25519VerificationKey2018 => {
                "Ed25519VerificationKey2018".to_string()
            }
            other => format!("{other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DID: &str = "did:ethr:0x1111111111111111111111111111111111111111";

    fn add_secp256k1_vm(builder: &mut DidDocumentBuilder, key: &str) {
        builder.add_verification_method(
            key,
            &format!("{DID}#{key}"),
            &VerificationKeyType::EcdsaSecp256k1VerificationKey2019,
            None,
            None,
            Some("deadbeef"),
            None,
            None,
            None,
        );
    }

    #[test]
    fn new_returns_empty_builder() {
        let b = DidDocumentBuilder::new();

        assert_eq!(b.id, "");
        assert!(b.verification_method.is_empty());
        assert!(b.authentication.is_empty());
        assert_eq!(b.key_index, 0);
        assert_eq!(b.service_index, 0);
        assert!(!b.deactivated);
    }

    #[test]
    fn base_for_did_populates_id_controller_method_and_relationships() {
        let b = DidDocumentBuilder::base_for_did(DID, 1).unwrap();

        assert_eq!(b.id, DID);
        assert_eq!(b.verification_method.len(), 1);
        let vm = &b.verification_method[0];
        assert_eq!(vm.key, "controller");
        assert_eq!(vm.id, format!("{DID}#controller"));
        assert_eq!(
            vm.type_,
            VerificationKeyType::EcdsaSecp256k1RecoveryMethod2020
        );
        assert_eq!(
            vm.blockchain_account_id.as_deref(),
            Some("eip155:1:0x1111111111111111111111111111111111111111"),
        );
        assert_eq!(b.authentication.len(), 1);
        assert_eq!(b.assertion_method.len(), 1);
    }

    #[test]
    fn add_verification_method_stores_provided_encoding() {
        let mut b = DidDocumentBuilder::new();
        b.set_id(DID);

        b.add_verification_method(
            "k1",
            &format!("{DID}#k1"),
            &VerificationKeyType::Ed25519VerificationKey2018,
            None,
            None,
            Some("deadbeef"),
            None,
            None,
            None,
        );

        assert_eq!(b.verification_method.len(), 1);
        let vm = &b.verification_method[0];
        assert_eq!(vm.public_key_hex.as_deref(), Some("deadbeef"));
        assert_eq!(vm.controller, DID);
    }

    #[test]
    fn add_delegate_key_increments_index_and_assigns_unique_id() {
        let mut b = DidDocumentBuilder::new();
        b.set_id(DID);

        b.add_delegate_key(
            "k1",
            &VerificationKeyType::EcdsaSecp256k1VerificationKey2019,
            None,
            None,
            Some("aa"),
            None,
            None,
            None,
        );
        b.add_delegate_key(
            "k2",
            &VerificationKeyType::EcdsaSecp256k1VerificationKey2019,
            None,
            None,
            Some("bb"),
            None,
            None,
            None,
        );

        assert_eq!(b.key_index, 2);
        assert_eq!(b.verification_method[0].id, format!("{DID}#delegate-1"));
        assert_eq!(b.verification_method[1].id, format!("{DID}#delegate-2"));
    }

    #[test]
    fn remove_delegate_key_removes_matching_method_and_is_noop_when_missing() {
        let mut b = DidDocumentBuilder::new();
        b.set_id(DID);
        add_secp256k1_vm(&mut b, "k1");
        add_secp256k1_vm(&mut b, "k2");

        b.remove_delegate_key("k1").unwrap();
        assert_eq!(b.verification_method.len(), 1);
        assert_eq!(b.verification_method[0].key, "k2");

        // Removing a key that doesn't exist must succeed silently.
        b.remove_delegate_key("nonexistent").unwrap();
        assert_eq!(b.verification_method.len(), 1);
    }

    #[test]
    fn add_service_auto_increments_index_when_id_omitted() {
        let mut b = DidDocumentBuilder::new();
        b.set_id(DID);

        b.add_service("s1", None, "LinkedDomains", "https://a.test");
        b.add_service("s2", Some("custom-id"), "LinkedDomains", "https://b.test");

        assert_eq!(b.service.len(), 2);
        assert_eq!(b.service[0].id, format!("{DID}#service-1"));
        // Caller-provided id wins over auto-generated one, but service_index
        // still increments to keep generated ids deterministic.
        assert_eq!(b.service[1].id, "custom-id");
        assert_eq!(b.service_index, 2);
    }

    #[test]
    fn remove_service_removes_matching_entry_and_is_noop_when_missing() {
        let mut b = DidDocumentBuilder::new();
        b.set_id(DID);
        b.add_service("s1", None, "LinkedDomains", "https://a.test");
        b.add_service("s2", None, "LinkedDomains", "https://b.test");

        b.remove_service("s1").unwrap();
        assert_eq!(b.service.len(), 1);
        assert_eq!(b.service[0].key, "s2");

        b.remove_service("nonexistent").unwrap();
        assert_eq!(b.service.len(), 1);
    }

    #[test]
    fn set_also_known_as_and_deactivate_setters_update_internal_state() {
        let mut b = DidDocumentBuilder::new();

        b.set_also_known_as(vec!["did:example:alias".to_string()]);
        b.deactivate();

        assert_eq!(
            b.also_known_as.as_deref(),
            Some(&["did:example:alias".to_string()][..])
        );
        assert!(b.deactivated());
    }

    #[test]
    fn build_emits_document_with_all_five_verification_relationships() {
        let mut b = DidDocumentBuilder::new();
        b.set_id(DID);
        add_secp256k1_vm(&mut b, "k1");

        b.add_authentication_reference("k1").unwrap();
        b.add_assertion_method_reference("k1").unwrap();
        b.add_key_agreement_reference("k1").unwrap();
        b.add_capability_invocation_reference("k1").unwrap();
        b.add_capability_delegation_reference("k1").unwrap();

        let doc = b.build().unwrap();

        let rels = &doc.verification_relationships;
        assert_eq!(rels.authentication.len(), 1);
        assert_eq!(rels.assertion_method.len(), 1);
        assert_eq!(rels.key_agreement.len(), 1);
        assert_eq!(rels.capability_invocation.len(), 1);
        assert_eq!(rels.capability_delegation.len(), 1);
        assert_eq!(doc.verification_method.len(), 1);
    }

    #[test]
    fn build_includes_controller_alsoknownas_and_jsonld_context() {
        let mut b = DidDocumentBuilder::new();
        b.set_id(DID);
        b.set_controller("did:ethr:0x2222222222222222222222222222222222222222");
        b.set_also_known_as(vec!["https://example.com/identity".to_string()]);

        let doc = b.build().unwrap();

        assert!(doc.controller.is_some());
        assert_eq!(doc.also_known_as.len(), 1);
        assert!(doc.property_set.contains_key("@context"));
    }

    #[test]
    #[should_panic(expected = "Verification method not found")]
    fn add_authentication_reference_errors_when_key_unknown() {
        let mut b = DidDocumentBuilder::new();
        b.set_id(DID);

        b.add_authentication_reference("missing").unwrap();
    }
}
