use crate::did::didpeer::{DIDPeer, DidPeerService};
use crate::did::{VerificationMethodKey, VerificationRelationshipType};
use crate::didcomm::agent::Agent;
use crate::didcomm::connection::in_mem::InMemConnectionService;
use crate::didcomm::connection::{
    ConnectionRecord, ConnectionService, ConnectionState, CreateOptions,
};
use crate::inmem::kms::{KeyHandle, LocalKms};
use crate::kms::{KeyType, Kms};
use serde_json::json;

pub async fn create_test_connection(
    agent: &Agent<LocalKms, KeyHandle, InMemConnectionService>,
) -> ConnectionRecord {
    let (_, my_kh) = agent
        .kms()
        .create_and_handle(KeyType::P256, Default::default())
        .await
        .unwrap();

    let (_, their_kh) = agent
        .kms()
        .create_and_handle(KeyType::P256, Default::default())
        .await
        .unwrap();

    // TODO: Fix issue while trying construct with DIDPeerService struct
    let service: DidPeerService = serde_json::from_value(json! ({
        "id": "#didcomm-1",
        "type": "DIDCommMessaging",
        "serviceEndpoint": {
            "uri": agent.configuration().endpoint.to_string(),
            "accept": [
                "didcomm/v2",
                "didcomm/aip2;env=rfc587"
            ],
            "routingKeys": ["#key-0"]
        }
    }))
    .unwrap();

    let my_did = DIDPeer::generate_did_peer4(
        &[VerificationMethodKey {
            key: &my_kh,
            verification_relationships: vec![
                VerificationRelationshipType::Authentication,
                VerificationRelationshipType::Assertion,
                VerificationRelationshipType::KeyAgreement,
            ]
            .into_iter()
            .collect(),
        }],
        &vec![service.clone()],
    )
    .unwrap();

    let their_did = DIDPeer::generate_did_peer4(
        &[VerificationMethodKey {
            key: &their_kh,
            verification_relationships: vec![
                VerificationRelationshipType::Authentication,
                VerificationRelationshipType::Assertion,
                VerificationRelationshipType::KeyAgreement,
            ]
            .into_iter()
            .collect(),
        }],
        &vec![service],
    )
    .unwrap();

    let mut connection_record = agent
        .connection_service()
        .create_connection(
            &my_did,
            CreateOptions {
                role: Default::default(),
                state: ConnectionState::Completed,
                label: None,
                alias: None,
                auto_accept: None,
                pthid: "".to_string(),
                metadata: Default::default(),
            },
        )
        .await
        .unwrap();
    connection_record.their_did = Some(their_did);
    agent
        .connection_service()
        .update_connection(connection_record.clone())
        .await
        .unwrap();

    connection_record
}
