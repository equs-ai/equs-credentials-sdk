use serde_json::json;

use crate::didcomm::protocol::aries::issuance::issuer::CredentialInfo;
use crate::inmem::kms::LocalKms;
use crate::kms::KeyType;
use crate::utils::test_utils::create_did_and_key_metadata_by_key_type;

pub async fn credential_info(kms: &LocalKms) -> CredentialInfo {
    let (_, iss_key_metadata) =
        create_did_and_key_metadata_by_key_type(kms, KeyType::Ed25519).await;

    let claims = json!({
        "type": ["PermanentResident", "Person"],
        "givenName": "JANE",
        "familyName": "SMITH",
        "gender": "Female",
        "image": "data:image/png;base64,iVBORw0KGgoAA...Jggg==",
        "id": "urn:uuid:7a6cafb9-11c3-41a8-98d8-8b5a45c2548f",
        "residentSince": "2015-01-01",
        "commuterClassification": "C1",
        "birthCountry": "Arcadia",
        "birthDate": "1978-07-17"
    })
    .try_into()
    .unwrap();

    let context = vec![
        "https://www.w3.org/2018/credentials/v1".to_string(),
        "https://w3id.org/citizenship/v1".to_string(),
    ];
    let types = vec!["PermanentResidentCard".to_string()];

    CredentialInfo::new(context, types, claims, 365, iss_key_metadata, None).unwrap()
}
