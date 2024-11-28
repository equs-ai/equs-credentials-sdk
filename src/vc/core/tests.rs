pub mod fixtures {
    use crate::crypto::Alg;
    use crate::vc::core::tests::utils::CredTestCase;
    use crate::vc::core::{
        CredentialDefinition, CredentialOffer, CredentialOfferContent, IssuerMetadata, KeyMetadata,
    };
    use crate::vc::formats::json_ld_vc;
    use serde_json::{json, Value};
    use ssi::core::uri;
    use ssi::one_or_many::OneOrMany;
    use ssi::vc::{Contexts, CredentialSubject};
    use ssi_ldp::Context;
    use std::collections::HashMap;

    pub const ISSUER_ID: &str = "issuer-id";
    pub const VERIFIER_ID: &str = "verifier-id";
    pub const CRED_DEF_ID: &str = "CRED_DEF_ID";
    pub const CRED_OFFER_ID: &str = "CRED_OFFER_ID";

    pub const VCT: &str = "https://issuer.net/cred_schema";
    pub const CRED_TYE: &str = "PermanentResidentCard";

    pub fn fake_ldp_vc_cred() -> json_ld_vc::Credential {
        json_ld_vc::Credential {
            context: Contexts::One(Context::URI(uri::URI::String(
                "https://placeholder.com".to_string(),
            ))),
            id: None,
            type_: OneOrMany::One("type".to_string()),
            credential_subject: OneOrMany::One(CredentialSubject {
                id: None,
                property_set: None,
            }),
            issuer: None,
            issuance_date: None,
            proof: None,
            expiration_date: None,
            credential_status: None,
            terms_of_use: None,
            evidence: None,
            credential_schema: None,
            refresh_service: None,
            property_set: None,
        }
    }

    pub fn sample_constraints() -> Value {
        json!({
            "fields": [
                {
                    "path": ["$.givenName"],
                },
                {
                    "path": ["$.familyName"],
                }
            ]
        })
    }

    pub fn sample_issuer_metadata(
        key_metadata: KeyMetadata,
        case: &CredTestCase,
    ) -> IssuerMetadata {
        IssuerMetadata {
            issuer_id: ISSUER_ID.to_string(),
            cred_defs: vec![sample_cred_def(case, key_metadata)],
            protocol_data: None,
        }
    }

    pub fn sample_cred_def(case: &CredTestCase, key_metadata: KeyMetadata) -> CredentialDefinition {
        let proofs = HashMap::from([(case.pop_format.clone(), vec![Alg::ES256])]);

        CredentialDefinition {
            cred_def_id: CRED_DEF_ID.into(),
            format: case.format.clone(),
            claims: Default::default(),
            supported_proofs: Some(proofs),
            supported_signing_algs: Some(vec![Alg::ES256]),
            display: None,
            protocol_data: case.protocol_data.clone(),
            key_metadata,
        }
    }

    pub fn sample_cred_def_offer(case: &CredTestCase) -> CredentialOffer {
        CredentialOffer {
            cred_offer_id: None,
            issuer_id: ISSUER_ID.to_string(),
            cred_def_id: CRED_DEF_ID.into(),
            content: CredentialOfferContent::CredDef(sample_cred_def(case, fake_key_metadata())),
            protocol_data: None,
        }
    }

    pub fn sample_proofs_offer(case: &CredTestCase) -> CredentialOffer {
        let proofs = HashMap::from([(case.pop_format.clone(), vec![Alg::ES256])]);

        CredentialOffer {
            cred_offer_id: Some(CRED_OFFER_ID.to_string()),
            issuer_id: ISSUER_ID.to_string(),
            cred_def_id: CRED_DEF_ID.into(),
            content: CredentialOfferContent::SupportedProofs(Some(proofs)),
            protocol_data: None,
        }
    }

    fn fake_key_metadata() -> KeyMetadata {
        KeyMetadata {
            did_url: "did:example".to_string(),
            kid: "12345".to_string(),
        }
    }
}

pub mod utils {
    use crate::crypto::Key;
    use crate::did::DIDURL;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::nonce::LocalNonceGenerator;
    use crate::kms::{KeyHandle, KeyType, Kms};
    use crate::nonce::{Nonce, NonceGenerator};
    use crate::utils::test_utils::create_did_url_and_key_handle_kid;
    use crate::vault::CredentialEntry;
    use crate::vc::core::tests::fixtures::*;
    use crate::vc::core::{
        CredentialDefinitionData, CredentialRequest, CredentialRequestData, PresentationInput,
        Proof,
    };
    use crate::vc::formats::json_ld_vc::JsonLdAPI;
    use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
    use crate::vc::formats::{json_ld_vc, sd_jwt_vc, HasCredential, VerifyOptions};
    use crate::vc::pop::jwt_pop::{JwtProofOfPossession, SignerWrapper};
    use crate::vc::pop::{GenerateOptions, ProofOfPossession};
    use crate::vc::{pop, ClaimFormat, Claims, Credential, Presentation, VCFormat, VCFormatsAPI};
    use oid4vci::openidconnect;
    use oid4vci::proof_of_possession::{ProofOfPossessionBody, ProofOfPossessionController};
    use serde_json::{json, Map, Value};
    use time::{Duration, OffsetDateTime};
    use uuid::Uuid;

    pub async fn random_nonce() -> Nonce {
        let nonce_gen = LocalNonceGenerator::default();
        nonce_gen.generate().await.unwrap()
    }

    pub struct CredTestCase {
        pub format: VCFormat,
        pub pop_format: pop::Format,
        pub protocol_data: Option<CredentialDefinitionData>,
        pub claim_format: ClaimFormat,
        pub type_: String,
        pub claims: Value,
    }

    impl CredTestCase {
        pub fn sd_jwt() -> CredTestCase {
            CredTestCase {
                format: VCFormat::SdJwtVc,
                pop_format: pop::Format::Jwt,
                protocol_data: Some(CredentialDefinitionData::SdJwt {
                    vct: VCT.to_owned(),
                    disclosures: vec!["$.givenName".to_owned(), "$.familyName".to_owned()],
                    lifetime: None,
                }),
                claim_format: ClaimFormat::SdJwtVc {
                    jwt_alg_values: vec!["ES256".to_string()],
                    kb_alg_values: vec!["ES256".to_string()],
                },
                type_: VCT.to_owned(),
                claims: json!({
                    "givenName": "Jane",
                    "familyName": "Smith",
                    "birthDate": "1978-07-17"
                }),
            }
        }

        pub fn ldp_vc() -> CredTestCase {
            CredTestCase {
                format: VCFormat::LdpVc,
                pop_format: pop::Format::Jwt,
                protocol_data: Some(CredentialDefinitionData::Ldp {
                    contexts: vec![
                        "https://www.w3.org/2018/credentials/v1".to_string(),
                        "https://w3id.org/citizenship/v1".to_string(),
                    ],
                    vc_types: vec![CRED_TYE.to_owned()],
                }),
                claim_format: ClaimFormat::LdpVc {
                    proof_type: vec!["EcdsaSecp256r1Signature2019".to_string()],
                },
                type_: CRED_TYE.to_owned(),
                claims: json!({
                    "type": ["PermanentResident", "Person"],
                    "givenName": "Jane",
                    "familyName": "Smith",
                    "gender": "female",
                    "residentSince": "2015-01-01",
                    "commuterClassification": "C1",
                    "birthCountry": "Arcadia",
                    "birthDate": "1978-07-17"
                }),
            }
        }
    }

    impl CredTestCase {
        pub async fn assert_proof_of_possession(&self, proof: Proof, nonce: &Nonce, did_url: &str) {
            assert_eq!(proof.format, self.pop_format.to_string());

            let (v_did_url, _) = match &self.pop_format {
                pop::Format::Jwt => JwtProofOfPossession::verify(
                    proof.proof.clone(),
                    nonce,
                    pop::VerifyOptions {
                        cred_iss_id: ISSUER_ID.into(),
                        client_id: None,
                        ..Default::default()
                    },
                )
                .await
                .unwrap(),
                _ => unimplemented!(),
            };

            assert!(did_url.starts_with(&v_did_url.did))
        }

        pub async fn assert_credential(&self, vc: &Credential) {
            match (&self.format, vc) {
                (VCFormat::SdJwtVc, Credential::SdJwt(cred)) => {
                    SdJwtAPI::verify_vc(cred, VerifyOptions {}).await.unwrap();
                }
                (VCFormat::LdpVc, Credential::LdpVc(cred)) => {
                    JsonLdAPI::verify_vc(cred, VerifyOptions {}).await.unwrap();
                }
                _ => unimplemented!(),
            }
        }

        pub async fn assert_presentation(&self, vp: &Presentation, vc: &Credential) {
            match &self.format {
                VCFormat::SdJwtVc => {
                    assert!(matches!(vp, Presentation::SdJwtVp(_)));
                }
                VCFormat::LdpVc => {
                    assert!(matches!(vp, Presentation::LdpVp(_)))
                }
                _ => unimplemented!(),
            }

            let vp_vc = &vp.get_credential().unwrap();

            match &self.format {
                VCFormat::SdJwtVc => match (vc, vp_vc) {
                    (Credential::SdJwt(vc_cred), Credential::SdJwt(vp_vc_cred)) => {
                        assert_eq!(vp_vc_cred, SdJwtAPI::strip_disclosures(vc_cred).unwrap());
                    }
                    (_, _) => unimplemented!(),
                },
                _ => assert_eq!(vp_vc, vc),
            }
        }

        pub async fn assert_verified_claims(&self, verified_claims: &Map<String, Value>) {
            let verified_claims = match &self.format {
                VCFormat::LdpVc => verified_claims
                    .get("credentialSubject")
                    .unwrap()
                    .as_object()
                    .unwrap(),
                _ => verified_claims,
            };

            let case_claims = self.claims.as_object().unwrap();
            for (name, val) in case_claims {
                let verified = verified_claims.get(name).unwrap();
                assert_eq!(val, verified)
            }
        }

        pub fn invalid_cred(&self) -> Credential {
            match &self.format {
                VCFormat::SdJwtVc => Credential::SdJwt("invalid".to_string()),
                VCFormat::LdpVc => Credential::LdpVc(fake_ldp_vc_cred()),
                _ => unimplemented!(),
            }
        }

        pub fn create_cred_request(&self, proof: String) -> CredentialRequest {
            CredentialRequest {
                cred_def_id: CRED_DEF_ID.to_string(),
                cred_offer_id: None,
                proof: Proof {
                    format: self.pop_format.to_string(),
                    proof,
                },
                protocol_data: None,
            }
        }

        pub fn create_cred_request_with_pop_tolerance(
            &self,
            proof: String,
            tolerance: Duration,
        ) -> CredentialRequest {
            let mut cred_req = self.create_cred_request(proof);
            cred_req.protocol_data = Some(CredentialRequestData {
                proof_tolerance: Some(tolerance),
            });

            cred_req
        }

        pub fn create_presentation_input(&self) -> PresentationInput {
            let constraints = serde_json::from_value(sample_constraints()).unwrap();

            PresentationInput {
                id: Uuid::new_v4().to_string(),
                format: self.claim_format.clone(),
                type_: self.type_.clone(),
                constraints,
            }
        }

        pub async fn generate_pop(&self, kms: &LocalKms, nonce: &Nonce, kt: KeyType) -> String {
            let (hld_did_url, h_kid, h_kh) = create_did_url_and_key_handle_kid(kms, kt).await;

            match &self.pop_format {
                pop::Format::Jwt => JwtProofOfPossession::generate(
                    &hld_did_url,
                    h_kh,
                    nonce,
                    GenerateOptions {
                        cred_iss_id: ISSUER_ID.to_string(),
                        client_id: None,
                        lifetime: None,
                    },
                )
                .await
                .unwrap(),
                _ => unimplemented!(),
            }
        }

        pub async fn generate_pop_with_lifetime(
            &self,
            kms: &LocalKms,
            nonce: &Nonce,
            kt: KeyType,
            not_before: Option<OffsetDateTime>,
            exp: Option<OffsetDateTime>,
        ) -> String {
            let (hld_did_url, h_kid, h_kh) = create_did_url_and_key_handle_kid(kms, kt).await;
            let now = OffsetDateTime::now_utc();

            let pop = oid4vci::proof_of_possession::ProofOfPossession {
                body: ProofOfPossessionBody {
                    audience: ISSUER_ID.to_string(),
                    issuer: None,
                    not_before,
                    issued_at: Some(now),
                    expires_at: exp.unwrap_or(
                        OffsetDateTime::now_utc()
                            .checked_add(Duration::minutes(5))
                            .unwrap(),
                    ),
                    nonce: openidconnect::Nonce::new(nonce.secret().to_owned()),
                },
                controller: ProofOfPossessionController {
                    vm: Some(hld_did_url.to_owned()),
                    jwk: h_kh.jwk().unwrap(),
                },
            };

            let sgn = SignerWrapper { key: h_kh };

            pop.to_jwt_with_signer(sgn).await.unwrap()
        }

        pub async fn generate_vc(&self, kms: &LocalKms) -> CredentialEntry {
            let (hld_did_url, h_kid, h_kh) =
                create_did_url_and_key_handle_kid(kms, KeyType::P256).await;
            let (iss_did_url, _, i_kh) =
                create_did_url_and_key_handle_kid(kms, KeyType::P256).await;

            let credential = match (&self.format, &self.protocol_data) {
                (
                    VCFormat::SdJwtVc,
                    Some(CredentialDefinitionData::SdJwt {
                        vct, disclosures, ..
                    }),
                ) => {
                    let vc = Self::sd_jwt_vc(
                        &self.claims,
                        (&iss_did_url, i_kh),
                        (&hld_did_url, h_kh),
                        vct,
                        disclosures,
                    )
                    .await;

                    Credential::SdJwt(vc)
                }
                (
                    VCFormat::LdpVc,
                    Some(CredentialDefinitionData::Ldp {
                        contexts, vc_types, ..
                    }),
                ) => {
                    let vc = Self::json_ld_vc(
                        &self.claims,
                        (&iss_did_url, i_kh),
                        (&hld_did_url, h_kh),
                        contexts,
                        vc_types,
                    )
                    .await;

                    Credential::LdpVc(vc)
                }
                _ => unimplemented!(),
            };

            CredentialEntry {
                credential,
                kid: h_kid,
            }
        }

        pub async fn generate_vp(
            &self,
            kms: &LocalKms,
            entry: &CredentialEntry,
            nonce: &Nonce,
        ) -> Presentation {
            let kh = kms.get(&entry.kid).await.unwrap();

            match (&self.format, &self.protocol_data, &entry) {
                (
                    VCFormat::SdJwtVc,
                    Some(CredentialDefinitionData::SdJwt { disclosures, .. }),
                    CredentialEntry {
                        credential: Credential::SdJwt(vc),
                        ..
                    },
                ) => {
                    let vp = Self::sd_jwt_vp(vc, kh, nonce, disclosures).await;

                    Presentation::SdJwtVp(vp)
                }
                (
                    VCFormat::LdpVc,
                    _,
                    CredentialEntry {
                        credential: Credential::LdpVc(vc),
                        ..
                    },
                ) => {
                    let vp = Self::json_ld_vp(vc, kh, nonce).await;

                    Presentation::LdpVp(vp)
                }
                _ => unimplemented!(),
            }
        }

        async fn sd_jwt_vc(
            claims: &Claims,
            iss_data: (&DIDURL, impl KeyHandle),
            hld_data: (&DIDURL, impl KeyHandle),
            vct: &str,
            disclosures: &Vec<String>,
        ) -> sd_jwt_vc::Credential {
            let vc_meta = sd_jwt_vc::VCMetadata {
                vct: vct.to_string(),
                disclosures: disclosures.to_owned(),
                lifetime: Default::default(),
            };

            SdJwtAPI::create_vc(
                SdJwtAPI::resolve_claims(claims).unwrap(),
                iss_data,
                hld_data,
                vc_meta,
            )
            .await
            .unwrap()
        }

        async fn sd_jwt_vp(
            vc: &sd_jwt_vc::Credential,
            kh: impl KeyHandle,
            nonce: &Nonce,
            disclosures: &[String],
        ) -> sd_jwt_vc::Presentation {
            let vp_meta = sd_jwt_vc::VPMetadata {
                disclosures: disclosures
                    .iter()
                    .map(|d| (d.to_owned().replace("$.", ""), json!(true)))
                    .collect(),
            };

            SdJwtAPI::create_vp(vc, kh, nonce, VERIFIER_ID, vp_meta)
                .await
                .unwrap()
        }

        async fn json_ld_vc(
            claims: &Claims,
            iss_data: (&DIDURL, impl KeyHandle),
            hld_data: (&DIDURL, impl KeyHandle),
            contexts: &Vec<String>,
            vc_types: &Vec<String>,
        ) -> json_ld_vc::Credential {
            let vc_meta = json_ld_vc::VCMetadata::new(contexts.to_owned(), vc_types.to_owned());

            JsonLdAPI::create_vc(
                JsonLdAPI::resolve_claims(claims).unwrap(),
                iss_data,
                hld_data,
                vc_meta,
            )
            .await
            .unwrap()
        }

        async fn json_ld_vp(
            vc: &json_ld_vc::Credential,
            kh: impl KeyHandle,
            nonce: &Nonce,
        ) -> json_ld_vc::Presentation {
            let vp_meta = json_ld_vc::VPMetadata::new();

            JsonLdAPI::create_vp(vc, kh, nonce, VERIFIER_ID, vp_meta)
                .await
                .unwrap()
        }
    }
}
