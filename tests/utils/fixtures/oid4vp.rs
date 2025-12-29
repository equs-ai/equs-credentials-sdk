use crate::utils::helpers::create_did_keymetadata_keyhandle;
use agent_sdk::did::DIDURL;
use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::inmem::kms::{KeyHandle, LocalKms};
use agent_sdk::nonce::{Nonce, NonceHandler};
use agent_sdk::vc::claims::{Claim, Claims};
use agent_sdk::vc::core::KeyMetadata;
use agent_sdk::vc::dcql::{DCQL, DCQLCredential};
use agent_sdk::vc::metadata::{CredentialMetadataProcessor, DefaultMetadataProcessor};
use agent_sdk::vc::presentation_exchange::PresentationDefinition;
use agent_sdk::vc::{
    Credential, CredentialMetadata, JsonLdAPIVCMetadata, VCFormatsAPI, VCFormatsJsonLdAPI,
    VCFormatsSdJwtAPI, VCMetadata,
};
use agent_sdk::{crypto, nonce};
use async_trait::async_trait;
use openid4vp::core::input_descriptor::InputDescriptor;
use openid4vp::utils::NonEmptyVec;
use serde_json::json;
use ssi::dids::ssi_json_ld::IriRefBuf;
use std::str::FromStr;

pub type ValidateClaimsFunc = dyn Fn(Claims) + Send + Sync;
pub const NONCE: &str = "some_nonce";

pub enum Oid4VpTestCredentialFormat {
    SdJwt(VCMetadata),
    LdpVc(Box<JsonLdAPIVCMetadata>),
}

pub struct Oid4VpTestCredential {
    pub format: Oid4VpTestCredentialFormat,
    pub claims: Claims,
}

pub struct Oid4VpTestCase {
    pub credentials: Vec<Oid4VpTestCredential>,
    pub presentation_definition: PresentationDefinition,
    pub dcql: Option<DCQL>,
    pub validate: Box<ValidateClaimsFunc>,
}

pub const VERIFIER_URL: &str = "http://example.com";
pub const STATE: &str = "d7a4bdce-d46f-48b3-ad85-4fcc5e124ad8";

fn sample_jsonld_resident_card_credential() -> (Oid4VpTestCredential, InputDescriptor) {
    let format = Oid4VpTestCredentialFormat::LdpVc(Box::new(
        JsonLdAPIVCMetadata::new(
            vec![
                IriRefBuf::from_str("https://www.w3.org/2018/credentials/v1").unwrap(),
                IriRefBuf::from_str("https://w3id.org/citizenship/v1").unwrap(),
            ],
            vec![
                "VerifiableCredential".to_string(),
                "PermanentResident".to_string(),
            ],
            Some(time::Duration::days(5 * 365)),
        )
        .unwrap(),
    ));

    let credential = Oid4VpTestCredential {
        format,
        claims: json!({
            "type": ["PermanentResident", "Person"],
            "givenName": "John",
            "familyName": "Doe",
            "birthDate": "09/09/1989",
        })
        .try_into()
        .unwrap(),
    };

    let input_descriptor = serde_json::from_value(json!(
        {
            "id": "residentCard",
            "name": "Identity VC",
            "purpose": "We want an identity",
            "format": {
                "ldp_vc": {
                   "proof_type": [
                    "Ed25519Signature2018",
                    "EcdsaSecp256k1Signature2019"
                   ]
                }
            },
            "constraints": {
                "fields": [
                    {
                        "path": ["$.type"],
                        "filter": {
                            "type": "array",
                            "contains": {
                                "const": "PermanentResident"
                            },
                        }
                    }
                ]
            }
        }
    ))
    .unwrap();

    (credential, input_descriptor)
}

pub fn sample_dcql_query_ldp_vc() -> DCQL {
    let desc: DCQLCredential = serde_json::from_value(json!(
                  {
                      "id": "residentCard",
                      "format": "ldp_vc",
                      "meta": {},
                  }
    ))
    .unwrap();

    DCQL::new(vec![desc].try_into().unwrap())
}

pub fn sample_dcql_query_sdjwt() -> DCQL {
    let desc: DCQLCredential = serde_json::from_value(json!(
        {
            "id": "identity",
            "format": "dc+sd-jwt",
            "meta": {},
            "claims": [
                {
                    "path": [
                        "name"
                    ]
                }
            ]
        }
    ))
    .unwrap();

    DCQL::new(vec![desc].try_into().unwrap())
}

fn sample_sdjwt_identity_credential() -> (Oid4VpTestCredential, InputDescriptor) {
    let format = Oid4VpTestCredentialFormat::SdJwt(VCMetadata {
        vct: "https://credentials.example.com/identity_credential".to_owned(),
        lifetime: Some(time::Duration::days(365)),
        disclosures: vec![
            "$.name".to_owned(),
            "$.surname".to_owned(),
            "$.address".to_owned(),
        ],
        credential_status: None,
    });

    let credential = Oid4VpTestCredential {
        format,
        claims: json!({
            "name": "John",
            "surname": "Doe",
            "address": "221B Baker Street",
            "date": "09/09/1989",
        })
        .try_into()
        .unwrap(),
    };

    let input_descriptor = serde_json::from_value(json!(
        {
            "id": "identity",
            "name": "Identity VC",
            "purpose": "We want an identity",
            "format": {
                "dc+sd-jwt": {
                   "sd-jwt_alg_values": [
                      "ES256",
                      "EdDSA"
                   ],
                   "kb-jwt_alg_values": [
                      "ES256",
                      "EdDSA"
                   ]
                }
             },
            "constraints": {
                "fields": [
                    {
                        "path": ["$.vct"],
                        "filter": {
                            "type": "string",
                            "const": "https://credentials.example.com/identity_credential"
                        }
                    },
                    {
                        "path": ["$.name"]
                    }
                ]
            }
        }
    ))
    .unwrap();

    (credential, input_descriptor)
}

fn sample_sdjwt_degree_credential() -> (Oid4VpTestCredential, InputDescriptor) {
    let format = Oid4VpTestCredentialFormat::SdJwt(VCMetadata {
        vct: "https://credentials.example.com/degree_credential".to_owned(),
        lifetime: Some(time::Duration::days(365)),
        disclosures: vec![
            "$.name".to_owned(),
            "$.surname".to_owned(),
            "$.address".to_owned(),
        ],
        credential_status: None,
    });

    let credential = Oid4VpTestCredential {
        format,
        claims: json!({
            "name": "John",
            "surname": "Doe",
            "degree": {
                "type": "BachelorDegree",
                "name": "Bachelor of Science and Arts"
            },
            "date": "09/09/2002",
        })
        .try_into()
        .unwrap(),
    };

    let input_descriptor = serde_json::from_value(json!(
        {
            "id": "Degree1",
            "name": "Degree VC",
            "format": {
                "dc+sd-jwt": {
                   "sd-jwt_alg_values": [
                      "ES256",
                      "EdDSA"
                   ],
                   "kb-jwt_alg_values": [
                      "ES256",
                      "EdDSA"
                   ]
                }
             },
            "constraints": {
                "fields": [
                    {
                        "path": ["$.vct"],
                        "filter": {
                            "type": "string",
                            "const": "https://credentials.example.com/degree_credential"
                        }
                    },
                    {
                        "path": ["$.name"]
                    }
                ]
            }
        }
    ))
    .unwrap();

    (credential, input_descriptor)
}

pub fn single_jsonld_presentation_case() -> Oid4VpTestCase {
    let (credential, descriptor) = sample_jsonld_resident_card_credential();
    let dcql = sample_dcql_query_ldp_vc();

    let presentation_definition = PresentationDefinition::new(
        "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed".to_string(),
        descriptor,
    );

    let validate: Box<ValidateClaimsFunc> = Box::new(|vp_response| {
        let presentations = extract_vp_claims(vp_response, "residentCard");

        assert_eq!(presentations.len(), 1);
        let presentation = &presentations[0];
        assert_eq!(
            presentation["verifiableCredential"]["credentialSubject"]["givenName"],
            Claim::String("John".to_string())
        );
        assert_eq!(
            presentation["verifiableCredential"]["credentialSubject"]["familyName"],
            Claim::String("Doe".to_string())
        );
        assert_eq!(
            presentation["verifiableCredential"]["credentialSubject"]["birthDate"],
            Claim::String("09/09/1989".to_string())
        );
    });

    Oid4VpTestCase {
        credentials: vec![credential],
        presentation_definition,
        validate,
        dcql: Some(dcql),
    }
}

pub fn single_sdjwt_presentation_case() -> Oid4VpTestCase {
    let (credential, descriptor) = sample_sdjwt_identity_credential();
    let dcql = sample_dcql_query_sdjwt();

    let presentation_definition = PresentationDefinition::new(
        "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed".to_string(),
        descriptor,
    );

    let validate: Box<ValidateClaimsFunc> = Box::new(|vp_response| {
        let presentations = extract_vp_claims(vp_response, "identity");
        assert_eq!(presentations.len(), 1);
        let presentation = &presentations[0];

        assert_eq!(
            &presentation["vct"],
            &Claim::String("https://credentials.example.com/identity_credential".to_string())
        );
        assert_eq!(&presentation["name"], &Claim::String("John".to_string()));
    });

    Oid4VpTestCase {
        credentials: vec![credential],
        presentation_definition,
        validate,
        dcql: Some(dcql),
    }
}

pub fn presentation_exchange_multiple_sdjwt_presentation_case() -> Oid4VpTestCase {
    let (cred_identity, descriptor_identity) = sample_sdjwt_identity_credential();
    let (cred_degree, descriptor_degree) = sample_sdjwt_degree_credential();

    let presentation_definition = PresentationDefinition::new(
        "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed".to_string(),
        descriptor_identity,
    )
    .add_input_descriptor(descriptor_degree);

    let validate: Box<ValidateClaimsFunc> = Box::new(|vp_response| {
        let mut presentations = extract_vp_claims(vp_response.clone(), "identity");
        assert_eq!(presentations.len(), 1);
        assert_eq!(
            &presentations[0]["vct"],
            &Claim::String("https://credentials.example.com/identity_credential".to_string())
        );
        assert_eq!(
            &presentations[0]["name"],
            &Claim::String("John".to_string())
        );

        presentations = extract_vp_claims(vp_response, "Degree1");
        assert_eq!(presentations.len(), 1);
        assert_eq!(
            &presentations[0]["vct"],
            &Claim::String("https://credentials.example.com/degree_credential".to_string())
        );
        assert_eq!(
            &presentations[0]["degree"]["type"],
            &Claim::String("BachelorDegree".to_string())
        );
    });

    Oid4VpTestCase {
        credentials: vec![cred_identity, cred_degree],
        presentation_definition,
        validate,
        dcql: None,
    }
}

pub fn dcql_multiple_sdjwt_presentation_case() -> Oid4VpTestCase {
    let (cred_identity_1, descriptor_identity_1) = sample_sdjwt_identity_credential();
    let (cred_identity_2, descriptor_identity_2) = sample_sdjwt_identity_credential();
    let (cred_degree, descriptor_degree) = sample_sdjwt_degree_credential();
    let dcql = sample_dcql_query_for_multiple_sdjwt();

    let presentation_definition = PresentationDefinition::new(
        "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed".to_string(),
        descriptor_degree,
    )
    .add_input_descriptor(descriptor_identity_1)
    .add_input_descriptor(descriptor_identity_2);

    let validate: Box<ValidateClaimsFunc> = Box::new(|vp_response| {
        // Check the first claims with 'multiple' set to true
        let mut presentations = extract_vp_claims(vp_response.clone(), "identity_1");
        assert_eq!(presentations.len(), 2);
        assert_eq!(
            &presentations[0]["vct"],
            &Claim::String("https://credentials.example.com/identity_credential".to_string())
        );
        assert_eq!(
            &presentations[0]["name"],
            &Claim::String("John".to_string())
        );

        assert_eq!(
            &presentations[1]["vct"],
            &Claim::String("https://credentials.example.com/identity_credential".to_string())
        );
        assert_eq!(
            &presentations[1]["surname"],
            &Claim::String("Doe".to_string())
        );

        // Check the second claims with 'multiple' set to false
        presentations = extract_vp_claims(vp_response.clone(), "identity_2");
        assert_eq!(presentations.len(), 1);
        assert_eq!(
            &presentations[0]["name"],
            &Claim::String("John".to_string())
        );

        // Check the third claims without 'multiple'
        presentations = extract_vp_claims(vp_response, "Degree1");
        assert_eq!(presentations.len(), 1);
        assert_eq!(
            &presentations[0]["vct"],
            &Claim::String("https://credentials.example.com/degree_credential".to_string())
        );
        assert_eq!(
            &presentations[0]["degree"]["type"],
            &Claim::String("BachelorDegree".to_string())
        );
    });

    Oid4VpTestCase {
        credentials: vec![cred_identity_1, cred_identity_2, cred_degree],
        presentation_definition,
        validate,
        dcql: Some(dcql),
    }
}

pub fn sample_dcql_query_for_multiple_sdjwt() -> DCQL {
    let desc1: DCQLCredential = serde_json::from_value(json!(
                  {
                      "id": "identity_1",
                      "format": "dc+sd-jwt",
                      "meta": {},
                      "claims": [
                        {"path": ["name"]},
                        {"path": ["surname"]},
                        {
                            "path": ["vct"],
                            "values": ["https://credentials.example.com/identity_credential"]
                        },
                      ],
                      "multiple": true
                  }
    ))
    .unwrap();
    let desc2: DCQLCredential = serde_json::from_value(json!(
                  {
                      "id": "identity_2",
                      "format": "dc+sd-jwt",
                      "meta": {},
                      "claims": [
                        {"path": ["name"]},
                      ],
                      "multiple": false
                  }
    ))
    .unwrap();

    let desc3: DCQLCredential = serde_json::from_value(json!(
      {
          "id": "Degree1",
          "format": "dc+sd-jwt",
          "meta": {},
          "claims": [
            {
              "path": [
                "name"
              ]
            },
            {
              "path": [
                "vct"
              ],
              "values": [
                "https://credentials.example.com/degree_credential"
              ]
            }
          ]
      }
    ))
    .unwrap();

    DCQL::new(vec![desc1, desc2, desc3].try_into().unwrap())
}

fn extract_vp_claims(vp_response: Claims, vp_name: &str) -> Vec<Claims> {
    let Claim::Array(ref presentations) = vp_response["vp_token"][vp_name] else {
        panic!("Expected array of claims");
    };
    let mut claims: Vec<Claims> = vec![];
    for presentation in presentations {
        let Claim::Object(claim) = presentation else {
            panic!("Expected object of claims");
        };

        claims.push(Claims::from_map(claim.clone()))
    }

    claims
}

#[derive(Default)]
pub struct MockNonceHandler {}

#[async_trait]
impl NonceHandler for MockNonceHandler {
    async fn generate(&self) -> nonce::Result<Nonce> {
        Ok(Nonce::from_secret(NONCE.to_string()))
    }

    async fn validate(&self, _nonce: &Nonce) -> nonce::Result<bool> {
        Ok(true)
    }
}

pub(crate) async fn create_vc(
    format: Oid4VpTestCredentialFormat,
    holder_did_url: &str,
    holder_kid: String,
    holder_kh: impl crypto::Key,
    claims: Claims,
) -> (Credential, CredentialMetadata) {
    println!("claims: {:?}", claims);

    // Generate Issuer DID and Key
    let kms = LocalKms::new();
    let (did, key_metadata, kh) = create_did_keymetadata_keyhandle(&kms).await;
    println!("Issuer DID: {}", did);

    match format {
        Oid4VpTestCredentialFormat::SdJwt(metadata) => {
            let vc = VCFormatsSdJwtAPI::create_vc(
                claims.clone(),
                (DIDURL::new(&key_metadata.did_url).unwrap(), kh),
                (DIDURL::new(holder_did_url).unwrap(), holder_kh),
                metadata,
                UniversalResolver::default(),
            )
            .await
            .unwrap();

            println!("Credential: {}", vc);

            let credential = Credential::SdJwt(vc);
            let metadata = DefaultMetadataProcessor::resolve_metadata(
                &credential,
                KeyMetadata {
                    did_url: holder_did_url.to_string(),
                    kid: holder_kid,
                },
            )
            .unwrap();

            (credential, metadata)
        }
        Oid4VpTestCredentialFormat::LdpVc(metadata) => {
            let vc = VCFormatsJsonLdAPI::create_vc(
                claims,
                (DIDURL::new(&key_metadata.did_url).unwrap(), kh),
                (DIDURL::new(holder_did_url).unwrap(), holder_kh),
                *metadata,
                UniversalResolver::default(),
            )
            .await
            .unwrap();

            println!("Credential: {}", serde_json::to_string_pretty(&vc).unwrap());

            let credential = Credential::LdpVc(vc);
            let metadata = DefaultMetadataProcessor::resolve_metadata(
                &credential,
                KeyMetadata {
                    did_url: holder_did_url.to_string(),
                    kid: holder_kid,
                },
            )
            .unwrap();

            (credential, metadata)
        }
    }
}

pub(crate) async fn generate_did_key_and_vm(kms: &LocalKms) -> (KeyMetadata, KeyHandle) {
    let (_, key_md, key_handle) = create_did_keymetadata_keyhandle(kms).await;

    (key_md, key_handle)
}

pub(crate) fn sample_dcql_query_for_mso_mdoc_vp_request() -> DCQL {
    let desc: DCQLCredential = serde_json::from_value(json!(
        {
            "id": "mDL",
            "format": "mso_mdoc",
            "meta": {
                "doctype_value": "org.iso.18013.5.1.mDL"
            },
            "claims": [
                {
                    "path": ["org.iso.18013.5.1", "given_name"],
                    "path": ["org.iso.18013.5.1", "family_name"],
                },
            ],
        }
    ))
    .unwrap();

    DCQL::new(NonEmptyVec::new(desc))
}
pub const SAMPLE_MDL_VP_TOKEN: &str = "o2d2ZXJzaW9uYzEuMGZzdGF0dXMAaWRvY3VtZW50c4GjZ2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbGlzc3VlclNpZ25lZKJqaXNzdWVyQXV0aIRDoQEmoRghWQKOMIICijCCAhGgAwIBAgIQc74-MgzUJTXc7tyYMuZpzjAKBggqhkjOPQQDAzAuMR8wHQYDVQQDDBZPV0YgTXVsdGlwYXogVEVTVCBJQUNBMQswCQYDVQQGDAJVUzAeFw0yNTEyMjIxNjIyMDRaFw0yNzAzMjIxNjIyMDRaMCwxHTAbBgNVBAMMFE9XRiBNdWx0aXBheiBURVNUIERTMQswCQYDVQQGDAJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNMpGgWifT-45gxw-QfLo2eJQq0o5_7OrSwo_UQdpVudB6lmYyfxCFBku6actQ0wACWUqNJPu9aoH9M5K1gxpbqjggERMIIBDTAfBgNVHSMEGDAWgBSrZRvgVsKQU_Hdf2zkh75o3mDJ9TAOBgNVHQ8BAf8EBAMCB4AwFQYDVR0lAQH_BAswCQYHKIGMXQUBAjBMBgNVHRIERTBDhkFodHRwczovL2dpdGh1Yi5jb20vb3BlbndhbGxldC1mb3VuZGF0aW9uLWxhYnMvaWRlbnRpdHktY3JlZGVudGlhbDBWBgNVHR8ETzBNMEugSaBHhkVodHRwczovL2dpdGh1Yi5jb20vb3BlbndhbGxldC1mb3VuZGF0aW9uLWxhYnMvaWRlbnRpdHktY3JlZGVudGlhbC9jcmwwHQYDVR0OBBYEFMeu5XcoKKErCLWXaKJ8d9xxsgnEMAoGCCqGSM49BAMDA2cAMGQCMHUwhZzyxR_1ghmBBDpEiVTweK_RogRqLLfGa38YfNXXQLL7HOu0DX-mARNtxd5W8QIweuK4uJXGb6zMtW6QaxdXblp3v2Po7DlTLvD62LWXwxqPuQfOyN5HBAXSH8w9-a0bWQhn2BhZCGKmZ3ZlcnNpb25jMS4wb2RpZ2VzdEFsZ29yaXRobWdTSEEtMjU2Z2RvY1R5cGV1b3JnLmlzby4xODAxMy41LjEubURMbHZhbHVlRGlnZXN0c6Jxb3JnLmlzby4xODAxMy41LjG4KBJYIHj5UWQbOz60rpuinYkpdSZxRz2BLi5wH8RyGtqU3SgTGCZYIDQb1MSS4sdqcE1HVQf9jIefNUHTVPd2zKfW-aB-DPf4GDJYIPI4sD2oqpY96qNrd98Cv7GXeOMFl3osd_5g2JJTQT0oC1ggKXDQAfGOiroU-Tdu8h_1EefWnAdmjIW3Kgj-jiuj0zsAWCCHSBWA3N7p9doBwhxN74Z-kT6b8lz6Gsxq6AOAoXY1jRghWCASXoRJadDJ0buzCG6lq5_csr4FjzUCRnTEUhSnlEvaNxgrWCB6GJDE2VK6x77CmPU2mfcIpj7EgygCTQr79gxpdGUwAAlYIP3CNmLJIasO_tM-fpU6Jz042PSFAhIiG66Od0-UtrSBEFggVWBEQsSrGdie7mMuD6mDCwSmF5ydgg0DlHm1hgndTcoYH1ggiXCkNE7Tnt_AElCb0EzjV4hRdO9IbZOikn8ROkI3PWkKWCCSUDdDWICEnysNE8xkvGgbdt4AryKWBhvwYLd2Unh_fgRYIDHbczG47oplSAF8sh2IdNF2VnPwb_uuYoe_DgZyJMaaA1ggvVhZZYQfvnEw95aKs6tWmjN-2JJk9pHk8pCogmpFD48VWCBG93gDOJtUaEBMh5kBb9iOpE92OR2mgexCS7akXJmUyBZYIDey-ILlg5dvthK9tZXpiWI9g_e611rRzjlk9abtLZVWGDBYICxM8vxe1ybXsdWf0bw4V1LQg9H1aKoh8PtcnQzEYcaZBVggbbSz5MQd8MdvYEmu-ENyANJDgofI99BdKJ5gn_re-soYHFgg19-6etpBTwqJINSUXU6sBteIBgm-JpDy9M-cWHqyDUQYHlggsPiZEYkARmvB-4caL29gtlNx0R9g5u-C2FV206zlaW4NWCBtyQxE_jm6SmDdST0aJHrps3IQsrKLlOiA-5RBWMcaMxgkWCBWSf_dhXb1_5BQfVwEZRDoCYXVto7jpqYIW2EtAAFLVxglWCDj2qTpjq3YF1ZB-J4y6Xped9OrVLvYTW9g-bgI8pxfiA5YIFSfx6blTpNkmgIp_hLWaJAqbu8-3ouZdufKgVhayf7MGCxYILJ6Y_G34zZNBq9J0rwow8E6iXJ0xx03XhFHS9WNbTeBD1ggIoVkit6q1rDp2_Np4KOe2nMN6XDlhWzzKsFDDbxYo_wYLVgg_HF_lPcG2htLsSE-CcmzhSK3DaU8bzRapo2bIiYEChwYGVggIDYweo8SPf_0-jU-VzKUkT0bC82Y4P6T6ElYR8iBywAXWCDgX-Y7o9AwXAPj1kSpLJjkFUuVuH6CfZspEMGXsR0KMRNYIGQHqJ6ObelPFGiz5m5rYeT-aD7ockTvybobbgLYmUFXAlggJdvdJTYZXaLVmo3Oc505Dz4MZggn1kuZWsG7FEb-dZ0YI1ggIbZclPyW1xTRatjNxj-GoNGnL6PnjQ8pH1_It8ral9IUWCA9Dn4u8MQzgk2gqPRKbBRV78YDvzCaYBIFirYcm3zVWAZYIIU-GnuguVsJr4pWMLnAojer4J5aIpm10zCBTkWlx0C9GCBYIJPpQ8H6HcGYbFZncdYvUuTAVmqGaJcupWJ01RPzmVv8EVggpluYq2pcQYwwkURDvzw-2fn10tgWAGluuZHnfPxrxq4YMVgga4tFNd4t0DM6nxTrSrDZ_wX_0YetX-naCB81NE3Sj2kYL1gg0GQ_kbWJOuxbCqKBUXUEnuuK4Y1ArgQwiNtrbb6_qAUYKVggBE53O1GmNfXnPq_lhcZEc1qmvM_GjPgz7YDQHYnlaqAYKFgg0xE_J0giEkshUTT1QISwIqMr_QgTt5SaXf--xOvDj6oYLlggWyT5gCHmwpwF_oIhWRL8r62D_E4mNpRkxYNGu0wEv3d3b3JnLmlzby4xODAxMy41LjEuYWFtdmGrB1gglPCDrDi-B0B27Pekz0Yr7BgFQeO-4hFZV7m5Vra8q3sYGlggOJpORk7R8kXdh2siD4CSSMOIEWFDcTHr-RmDjiYn0YAYKlggm-bzD38dApsZQB1Ej63Dk0-TgAAQa8qQhLQOBuw0-8AYG1ggr-huIb2CQmte9AbHIxL1r9NNjR1TdsGjGkgUSEGjWHEIWCB4QSg0CU_TVTqGtXRxSBXbPEYWN5YbUtKhuz_o-pt90xgdWCCULn59sTrl2MPn7zCW4-_Fu0E30NWtkQe_OIPYC7NzNAxYIFue16N-f9XHk8SBuue3Rq3XChfRrUwJngDBW-EJq_3wAVggAlAPuCzNToDisOfvX5uBY7q-AecL1b9sSpazSOO5fHIYGFggMU5ECfjG_L6pT7T-_Vfvg-BVd_HxtSISv0V_tH8P0p4YIlggWWyBDimoUoa-be9f_WYQuNYQweMSp4FIRslFUwSUeoIYJ1ggry2Zew_B71BWfuZjkcA3DE8FxUWBJfpqxy6HeBQsCBNtZGV2aWNlS2V5SW5mb6FpZGV2aWNlS2V5pAECIAEhWCAC_Q0jUrXVhYNPjSo3YymF6a4qnYISXEtDRfl9NVc77iJYIEK8n0Ob1GILTTOVQWoyyV5LetLyOuoNqSWbeydmylwVbHZhbGlkaXR5SW5mb6Nmc2lnbmVkwHQyMDI1LTEyLTIzVDE1OjIyOjA1Wml2YWxpZEZyb23AdDIwMjUtMTItMjNUMTU6MjI6MDVaanZhbGlkVW50aWzAdDIwMjYtMTItMjNUMTY6MjI6MDVaWEAuF_4XR-BnvcaQpTXxv_jku1h_lwsE_wxBrkgztSXpazep7WxBH6wRJoCrPEByJNl_PSIapw7Q-IdTW9A4VLMuam5hbWVTcGFjZXOhcW9yZy5pc28uMTgwMTMuNS4xgtgYWFSkaGRpZ2VzdElEGCZmcmFuZG9tUOgMidLSvJw2SHAJ9IxjRYNxZWxlbWVudElkZW50aWZpZXJqZ2l2ZW5fbmFtZWxlbGVtZW50VmFsdWVlRXJpa2HYGFhZpGhkaWdlc3RJRBJmcmFuZG9tUM_9v8xbuctmGv1lw_v_zjxxZWxlbWVudElkZW50aWZpZXJrZmFtaWx5X25hbWVsZWxlbWVudFZhbHVlak11c3Rlcm1hbm5sZGV2aWNlU2lnbmVkompkZXZpY2VBdXRooW9kZXZpY2VTaWduYXR1cmWEQ6EBJqD2WEB09g4NW2Qvn6HfJ8RDBxdHwGKxl7ZowELWy-sEJqorZxKjsJd-JiuoFMOwvsg60xGSyYrGWjOcxe6bdY-ajDgpam5hbWVTcGFjZXPYGEGg";
pub const SAMPLE_IACA_CERT_1: &str = "-----BEGIN CERTIFICATE-----
MIICqDCCAi2gAwIBAgIQNurX5DFyLb9mx2OYJm+AIDAKBggqhkjOPQQDAzAuMR8w
HQYDVQQDDBZPV0YgTXVsdGlwYXogVEVTVCBJQUNBMQswCQYDVQQGDAJVUzAeFw0y
NDEyMDEwMDAwMDBaFw0zNDEyMDEwMDAwMDBaMC4xHzAdBgNVBAMMFk9XRiBNdWx0
aXBheiBURVNUIElBQ0ExCzAJBgNVBAYMAlVTMHYwEAYHKoZIzj0CAQYFK4EEACID
YgAE+QDye70m2O0llPXMjVjxVZz3m5k6agT+wih+L79b7jyqUl99sbeUnpxaLD+c
mB3HK3twkA7fmVJSobBc+9CDhkh3mx6n+YoH5RulaSWThWBfMyRjsfVODkosHLCD
nbPVo4IBDjCCAQowDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAw
TAYDVR0SBEUwQ4ZBaHR0cHM6Ly9naXRodWIuY29tL29wZW53YWxsZXQtZm91bmRh
dGlvbi1sYWJzL2lkZW50aXR5LWNyZWRlbnRpYWwwVgYDVR0fBE8wTTBLoEmgR4ZF
aHR0cHM6Ly9naXRodWIuY29tL29wZW53YWxsZXQtZm91bmRhdGlvbi1sYWJzL2lk
ZW50aXR5LWNyZWRlbnRpYWwvY3JsMB0GA1UdDgQWBBSrZRvgVsKQU/Hdf2zkh75o
3mDJ9TAfBgNVHSMEGDAWgBSrZRvgVsKQU/Hdf2zkh75o3mDJ9TAKBggqhkjOPQQD
AwNpADBmAjEA5f7FMEYm6e4EVsBCGs/6QPOLH3W3/sR3nepN/EY+od2U02s8reyV
DgyH9i5YBwNFAjEAntYi3uf5M4mLNxIKBqg2Km666ZgWxOLV+Sj/urS8n0WRqF1S
apDWfa/oeTyF0aJG
-----END CERTIFICATE-----";
pub const SAMPLE_IACA_CERT_2: &str = "-----BEGIN CERTIFICATE-----
MIIDlTCCAxygAwIBAgITZ1Q7u+8TXCBKFn6jmzvPwCx3bDAKBggqhkjOPQQDAzBb
MQswCQYDVQQGEwJYRzETMBEGA1UEChMKR29vZ2xlIExMQzEPMA0GA1UECxMGV2Fs
bGV0MSYwJAYDVQQDEx1JZGVudGl0eSBDcmVkZW50aWFsIFJvb3QgSUFDQTAeFw0y
NTAzMDQyMDUyMThaFw0zNTAzMDUwNjMyMTlaMFsxCzAJBgNVBAYTAlhHMRMwEQYD
VQQKEwpHb29nbGUgTExDMQ8wDQYDVQQLEwZXYWxsZXQxJjAkBgNVBAMTHUlkZW50
aXR5IENyZWRlbnRpYWwgUm9vdCBJQUNBMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE
10PwkmBoPbxLLzP2Uph7NU55nM130T+wp8/QMdPa/SKXzMBTHINFb/uh0LmvKnfg
k4wiDhREGM9ty/yuLB/ZT+2abS6cD7FDyvhVBzwNNR0VVsCDdqv2Ob8KaQzLAXLn
o4IBoDCCAZwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYD
VR0OBBYEFBpEaI07wxCy/QSQd9UO5UBlzxTpMB8GA1UdIwQYMBaAFBpEaI07wxCy
/QSQd9UO5UBlzxTpMIGNBggrBgEFBQcBAQSBgDB+MHwGCCsGAQUFBzAChnBodHRw
Oi8vcHJpdmF0ZWNhLWNvbnRlbnQtNjdmNWY0MzItMDAwMC0yOTJmLTkxZDYtYWMz
ZWIxNGU3YjY4LnN0b3JhZ2UuZ29vZ2xlYXBpcy5jb20vYWE3NjAzMGUwYjIyYTNh
OTVhOGIvY2EuY3J0MIGCBgNVHR8EezB5MHegdaBzhnFodHRwOi8vcHJpdmF0ZWNh
LWNvbnRlbnQtNjdmNWY0MzItMDAwMC0yOTJmLTkxZDYtYWMzZWIxNGU3YjY4LnN0
b3JhZ2UuZ29vZ2xlYXBpcy5jb20vYWE3NjAzMGUwYjIyYTNhOTVhOGIvY3JsLmNy
bDAhBgNVHRIEGjAYhhZodHRwczovL3d3dy5nb29nbGUuY29tMAoGCCqGSM49BAMD
A2cAMGQCMEleAuFo8yKVGk70NwJ/CzBt08mNHqBsxILZnTHwKvxXRkgDcXbwd931
bVvQoTYppQIwTCcq+Kic8KAe1Y2lu0ohvkxwST1s34ytFqJcElPddS76rX4rJLLW
wSde7pYC3LmY
-----END CERTIFICATE-----";
