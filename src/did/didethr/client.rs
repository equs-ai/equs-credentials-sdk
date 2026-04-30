use crate::did::didethr::registry::EthrDidRegistry;
use crate::did::didethr::types::block::Block;
use crate::did::didethr::types::did_doc_builder::DidDocumentBuilder;
use crate::did::didethr::types::did_events::{
    DidAttributeChanged, DidDelegateChanged, DidEvents, DidOwnerChanged,
};
use crate::did::didethr::types::{
    DID_RESOLUTION_FORMAT, DelegateType, DidDocAttribute, DidRecord, PublicKeyPurpose,
    VerificationKeyType,
};
use crate::did::universal::DIDResolver;
use crate::did::{ResolutionError, ResolutionOutput, SpruceDID};
use async_trait::async_trait;
use chrono::Utc;
use ssi::dids::DIDMethod;
use ssi::dids::document::Represented;
use ssi::dids::resolution::Options;
use std::collections::HashSet;

static ETHR_DID_METHOD: &str = "ethr";

pub struct DIDEthr {
    registries: Vec<EthrDidRegistry>,
}

impl DIDEthr {
    pub fn new(registries: Vec<EthrDidRegistry>) -> DIDEthr {
        Self { registries }
    }

    pub fn add_registry(&mut self, registry: EthrDidRegistry) -> Result<(), ResolutionError> {
        if self
            .registries
            .iter()
            .any(|r| r.chain_id() == registry.chain_id())
        {
            Err(ResolutionError::Internal(format!(
                "Registry for chain {:#?} already exists",
                registry.chain_id()
            )))?
        }
        self.registries.push(registry);
        Ok(())
    }
    pub fn get_registry_by_did(&self, did: &str) -> Result<&EthrDidRegistry, ResolutionError> {
        let parts: Vec<&str> = did.split(':').collect();

        // did:ethr consists of at least 3 parts (did, ethr, identifier/address)
        if parts.len() < 3 || parts[0] != "did" || parts[1] != "ethr" {
            return Err(ResolutionError::InvalidMethodSpecificId(did.to_owned()));
        }

        let target_chain_id = match parts.len() {
            // Case: did:ethr:0xADDRESS (Default to Mainnet)
            3 => 1,

            // Case: did:ethr:network:0xADDRESS
            4 => {
                let network_segment = parts[2];
                if let Some(stripped) = network_segment.strip_prefix("0x") {
                    // It's a Hex Chain ID (e.g., 0x89)
                    u64::from_str_radix(stripped, 16)
                        .map_err(|_| ResolutionError::InvalidMethodSpecificId(did.to_owned()))?
                } else {
                    // It's a Named Alias (e.g., "sepolia")
                    self.map_name_to_chain_id(network_segment)
                        .ok_or(ResolutionError::Internal("Chain not found".to_owned()))?
                }
            }
            _ => return Err(ResolutionError::InvalidMethodSpecificId(did.to_owned())),
        };

        self.registries
            .iter()
            .find(|r| r.chain_id() == target_chain_id)
            .ok_or(ResolutionError::Internal(
                "Ethr registry not found".to_owned(),
            ))
    }

    fn map_name_to_chain_id(&self, name: &str) -> Option<u64> {
        match name {
            "mainnet" => Some(1),
            "polygon" | "matic" => Some(137),
            "arbitrum" => Some(42161),
            "optimism" => Some(10),
            "gnosis" => Some(100),
            "sepolia" => Some(11155111),
            "holesky" => Some(17000),
            _ => None,
        }
    }
}

impl DIDMethod for DIDEthr {
    const DID_METHOD_NAME: &'static str = "ethr";
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for DIDEthr {
    async fn resolve_representation<'a>(
        &'a self,
        did: &'a SpruceDID,
        options: Options,
    ) -> Result<ResolutionOutput, ResolutionError> {
        DIDEthr::validate_did(did)?;

        let media_type = match options.accept.map(|v| v.to_string()) {
            Some(fmt) if fmt == DID_RESOLUTION_FORMAT => DID_RESOLUTION_FORMAT.to_string(),
            None => DID_RESOLUTION_FORMAT.to_string(),
            Some(accept) => {
                return Err(ResolutionError::Internal(format!(
                    "Resolver does not support the requested 'accept' format: {}",
                    accept
                )));
            }
        };

        let did_record = self
            .resolve(did, None)
            .await
            .map_err(|e| ResolutionError::Internal(e.to_string()))?;

        Ok(ResolutionOutput {
            document: Represented::new(
                serde_json::from_value(serde_json::to_value(&did_record.document).unwrap())
                    .unwrap(),
                ssi::dids::document::representation::Options::Json,
            ),
            document_metadata: ssi::dids::document::Metadata {
                deactivated: did_record.metadata.deactivated,
            },
            metadata: ssi::dids::resolution::Metadata {
                content_type: Some(media_type),
            },
        })
    }

    fn method_name(&self) -> String {
        Self::DID_METHOD_NAME.to_string()
    }
}

impl DIDEthr {
    async fn resolve(
        &self,
        did: &str,
        block: Option<&Block>,
    ) -> Result<DidRecord, ResolutionError> {
        let registry = self.get_registry_by_did(did)?;
        let mut did_doc_builder = DidDocumentBuilder::base_for_did(did, registry.chain_id())?;
        let did_changed_block = registry.get_did_changed(did).await?;

        if did_changed_block.is_none() {
            let document = did_doc_builder.build()?;
            return Ok(DidRecord {
                document,
                metadata: crate::did::didethr::types::resolution::DidMetadata::default(),
            });
        }

        let mut _version_id: Option<Block> = None;
        let mut next_version_id: Option<Block> = None;

        let registry = self.get_registry_by_did(did)?;

        let now = match block {
            Some(block) => registry.get_block(Some(block)).await?.timestamp,
            None => Utc::now().timestamp() as u64,
        };

        let did_history = self.receive_did_history(did, did_changed_block).await?;

        for (event_block, event) in did_history.into_iter().rev() {
            match block {
                Some(block) if event_block.value() > block.value() => {
                    if next_version_id.is_none() {
                        next_version_id = Some(event_block)
                    }
                    continue;
                }
                _ => {
                    _version_id = Some(event_block);
                }
            }

            self.handle_did_event(&mut did_doc_builder, &event, now)?;

            if did_doc_builder.deactivated() {
                break;
            }
        }

        let metadata = self.build_did_metadata(did_doc_builder.deactivated());

        Ok(DidRecord {
            document: did_doc_builder.build()?,
            metadata,
        })
    }
    async fn receive_did_history(
        &self,
        did: &str,
        first_block: Block,
    ) -> Result<Vec<(Block, DidEvents)>, ResolutionError> {
        let registry = self.get_registry_by_did(did)?;
        let mut history: Vec<(Block, DidEvents)> = Vec::new();
        let mut previous_block: Option<Block> = Some(first_block);
        let mut visited_blocks: HashSet<u64> = HashSet::new();

        while let Some(ref current_block) = previous_block {
            if current_block.is_none() {
                break;
            }
            let current_value = current_block.value();
            if !visited_blocks.insert(current_value) {
                break;
            }

            let logs = registry
                .get_did_events(did, Some(current_block), Some(current_block))
                .await?;
            if logs.is_empty() {
                break;
            }
            let mut next_previous: Option<Block> = None;
            for (block, event) in logs {
                let prev = event.previous_change();
                history.push((block, event));

                // Some blocks contain multiple events where previous_change can point
                // to the same block (or even a future one). Only follow strictly older
                // blocks, otherwise history traversal can loop forever.
                if !prev.is_none() && prev.value() < current_value {
                    match next_previous {
                        Some(ref current_next) if prev.value() < current_next.value() => {
                            next_previous = Some(prev);
                        }
                        None => {
                            next_previous = Some(prev);
                        }
                        _ => {}
                    }
                }
            }
            previous_block = next_previous;
        }
        Ok(history)
    }

    fn handle_did_event(
        &self,
        did_doc_builder: &mut DidDocumentBuilder,
        event: &DidEvents,
        now: u64,
    ) -> Result<(), ResolutionError> {
        match event {
            DidEvents::OwnerChanged(event) => self.handle_did_owner_changed(did_doc_builder, event),
            DidEvents::DelegateChanged(event) => {
                self.handle_did_delegate_changed(did_doc_builder, event, now)
            }
            DidEvents::AttributeChangedEvent(event) => {
                self.handle_did_attribute_changed(did_doc_builder, event, now)
            }
        }
    }

    fn handle_did_owner_changed(
        &self,
        did_doc_builder: &mut DidDocumentBuilder,
        event: &DidOwnerChanged,
    ) -> Result<(), ResolutionError> {
        let controller = format!("did:ethr:{}", event.owner.as_ref());
        did_doc_builder.set_controller(controller.as_ref());
        Ok(())
    }

    fn handle_did_delegate_changed(
        &self,
        did_doc_builder: &mut DidDocumentBuilder,
        event: &DidDelegateChanged,
        now: u64,
    ) -> Result<(), ResolutionError> {
        let registry = self.get_registry_by_did(&did_doc_builder.get_id())?;

        let event_index = event.key();
        let delegate_type = DelegateType::try_from(event.delegate_type.as_slice())?;

        if event.valid_to > now {
            did_doc_builder.add_delegate_key(
                &event_index,
                &VerificationKeyType::EcdsaSecp256k1RecoveryMethod2020,
                Some(
                    event
                        .delegate
                        .as_blockchain_id(registry.chain_id())
                        .as_str(),
                ),
                None,
                None,
                None,
                None,
                None,
            );
            match delegate_type {
                DelegateType::VeriKey => {
                    did_doc_builder.add_assertion_method_reference(&event_index)?;
                }
                DelegateType::SigAuth => {
                    did_doc_builder.add_authentication_reference(&event_index)?;
                }
            }
        } else {
            did_doc_builder.remove_delegate_key(&event_index)?;
            match delegate_type {
                DelegateType::VeriKey => {
                    did_doc_builder.remove_assertion_method_reference(&event_index)?;
                }
                DelegateType::SigAuth => {
                    did_doc_builder.remove_authentication_reference(&event_index)?;
                }
            }
        };
        Ok(())
    }

    fn handle_did_attribute_changed(
        &self,
        did_doc_builder: &mut DidDocumentBuilder,
        event: &DidAttributeChanged,
        now: u64,
    ) -> Result<(), ResolutionError> {
        let event_index = event.key();
        let attribute = DidDocAttribute::try_from(event.to_owned())?;

        match attribute {
            DidDocAttribute::PublicKey(key) => {
                if event.valid_to > now {
                    did_doc_builder.add_delegate_key(
                        &event_index,
                        &key.type_.into(),
                        None,
                        None,
                        key.public_key_hex.as_deref(),
                        key.public_key_base58.as_deref(),
                        key.public_key_base64.as_deref(),
                        None,
                    );
                    match key.purpose {
                        PublicKeyPurpose::VeriKey => {
                            did_doc_builder.add_assertion_method_reference(&event_index)?;
                        }
                        PublicKeyPurpose::SigAuth => {
                            did_doc_builder.add_authentication_reference(&event_index)?;
                        }
                        PublicKeyPurpose::Enc => {
                            did_doc_builder.add_key_agreement_reference(&event_index)?;
                        }
                    }
                } else {
                    did_doc_builder.remove_delegate_key(&event_index)?;
                    match key.purpose {
                        PublicKeyPurpose::VeriKey => {
                            did_doc_builder.remove_assertion_method_reference(&event_index)?;
                        }
                        PublicKeyPurpose::SigAuth => {
                            did_doc_builder.remove_authentication_reference(&event_index)?;
                        }
                        PublicKeyPurpose::Enc => {
                            did_doc_builder.remove_key_agreement_reference(&event_index)?;
                        }
                    }
                }
            }
            DidDocAttribute::Service(service) => {
                if event.valid_to > now {
                    did_doc_builder.add_service(
                        &event_index,
                        None,
                        &service.type_,
                        &service.service_endpoint,
                    );
                } else {
                    did_doc_builder.remove_service(&event_index)?;
                }
            }
        };
        Ok(())
    }

    fn build_did_metadata(&self, deactivated: bool) -> super::types::resolution::DidMetadata {
        super::types::resolution::DidMetadata {
            deactivated: Some(deactivated),
            ..Default::default()
        }
    }

    fn validate_did(did: &str) -> Result<(), ResolutionError> {
        let length = did.split(":").collect::<Vec<&str>>().len();
        if [3, 4].contains(&length) {
            return Ok(());
        }
        Err(ResolutionError::Internal(format!(
            "Not a valid did: {}",
            did
        )))
    }
}
