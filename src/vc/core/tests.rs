pub mod fixtures {
    use crate::crypto::Alg;
    use crate::vc::claims::Claims;
    use crate::vc::core::tests::utils::CredTestCase;
    use crate::vc::core::{
        CredentialDefinition, CredentialOffer, CredentialOfferContent, IssuerMetadata, KeyMetadata,
    };
    use crate::vc::formats::json_ld_vc;
    use iref::{IriRefBuf, UriBuf};
    use ssi::claims::data_integrity::Proofs;
    use ssi::claims::vc::syntax::IdOr;
    use ssi::claims::vc::v1::syntax::CredentialType;
    use ssi::json_ld::syntax::ContextEntry;
    use std::collections::HashMap;
    use std::str::FromStr;

    pub const ISSUER_ID: &str = "https://example.issuer.org";
    pub const VERIFIER_ID: &str = "https://example.verifier.org";
    pub const CRED_DEF_ID: &str = "CRED_DEF_ID";
    pub const CRED_OFFER_ID: &str = "CRED_OFFER_ID";

    pub const VCT: &str = "https://issuer.net/cred_schema";
    pub const CRED_TYPE: &str = "PermanentResident";

    pub fn fake_ldp_vc_cred() -> json_ld_vc::VC {
        let mut context = ssi::claims::vc::syntax::Context::default();
        context.insert(ContextEntry::IriRef(
            IriRefBuf::new("https://placeholder.com".to_string()).unwrap(),
        ));
        let types = ssi::claims::vc::syntax::Types::<CredentialType>::default();
        let cred = json_ld_vc::Credential {
            context,
            id: None,
            types,
            credential_subjects: ssi::claims::vc::syntax::NonEmptyVec::new(Claims::new()),
            issuer: IdOr::Id(UriBuf::from_str(ISSUER_ID).unwrap()),
            issuance_date: None,
            expiration_date: None,
            credential_status: vec![],
            terms_of_use: vec![],
            evidence: vec![],
            credential_schema: vec![],
            refresh_services: vec![],
            additional_properties: Default::default(),
        };

        json_ld_vc::VC::new(cred, Proofs::default())
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
    use crate::crypto::Signer;
    use crate::did::DIDURL;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::nonce::LocalNonceGenerator;
    use crate::kms::{KeyHandle, KeyType, Kms};
    use crate::nonce::{Nonce, NonceGenerator};
    use crate::utils::test_utils::create_did_url_and_key_handle_kid;
    use crate::vault::CredentialEntry;
    use crate::vc::claims::Claims;
    use crate::vc::core::tests::fixtures::*;
    use crate::vc::core::{
        CredentialDefinitionData, CredentialRequest, CredentialRequestData, PresentationInput,
        PresentationRestriction, Proof,
    };
    use crate::vc::formats::json_ld_vc::JsonLdAPI;
    use crate::vc::formats::sd_jwt_vc::SdJwtAPI;
    use crate::vc::formats::{json_ld_vc, sd_jwt_vc, HasCredential, VerifyOptions};
    use crate::vc::pop::jwt_pop::JwtProofOfPossession;
    use crate::vc::pop::{GenerateOptions, ProofOfPossession};
    use crate::vc::{pop, ClaimFormat, Credential, Presentation, VCFormat, VCFormatsAPI};
    use iref::IriRefBuf;
    use oid4vci::proof_of_possession::{ProofOfPossessionBody, ProofOfPossessionController};
    use serde_json::json;
    use std::str::FromStr;
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
        pub claims: Claims,
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
                })
                .try_into()
                .unwrap(),
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
                    vc_types: vec![CRED_TYPE.to_owned()],
                }),
                claim_format: ClaimFormat::LdpVc {
                    proof_type: vec!["EcdsaSecp256r1Signature2019".to_string()],
                },
                type_: CRED_TYPE.to_owned(),
                claims: json!({
                    "type": [CRED_TYPE.to_owned(), "Person"],
                    "givenName": "Jane",
                    "familyName": "Smith",
                    "gender": "female",
                    "residentSince": "2015-01-01",
                    "commuterClassification": "C1",
                    "birthCountry": "Arcadia",
                    "birthDate": "1978-07-17"
                })
                .try_into()
                .unwrap(),
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
                        audience: ISSUER_ID.into(),
                        issuer: None,
                        ..Default::default()
                    },
                )
                .await
                .unwrap(),
                _ => unimplemented!(),
            };

            assert!(did_url.starts_with(v_did_url.did().as_str()))
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
                _ => assert_eq!(
                    serde_json::to_value(vp_vc).unwrap(),
                    serde_json::to_value(vc).unwrap()
                ),
            }
        }

        pub async fn assert_verified_claims(&self, verified_claims: &Claims) {
            let verified_claims = match &self.format {
                VCFormat::LdpVc => {
                    let vcs = verified_claims.get("verifiableCredential").unwrap();

                    vcs.get("credentialSubject").unwrap()
                }
                _ => &verified_claims.clone().into(),
            };

            let case_claims = self.claims.claims();
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
            match self.format {
                VCFormat::SdJwtVc => PresentationInput {
                    id: Uuid::new_v4().to_string(),
                    format: Some(self.claim_format.name()),
                    restrictions: vec![
                        PresentationRestriction {
                            fields: vec!["$.vct".to_string()],
                            value: Some(self.type_.to_owned()),
                            optional: false,
                        },
                        PresentationRestriction {
                            fields: vec!["$.givenName".to_string(), "$.familyName".to_string()],
                            value: None,
                            optional: false,
                        },
                    ],
                },
                VCFormat::LdpVc => PresentationInput {
                    id: Uuid::new_v4().to_string(),
                    format: Some(self.claim_format.name()),
                    restrictions: vec![
                        PresentationRestriction {
                            fields: vec!["$.type[*]".to_string()],
                            value: Some(self.type_.to_owned()),
                            optional: false,
                        },
                        PresentationRestriction {
                            fields: vec![
                                "$.credentialSubject.givenName".to_string(),
                                "$.credentialSubject.familyName".to_string(),
                            ],
                            value: None,
                            optional: false,
                        },
                    ],
                },
                _ => PresentationInput {
                    id: Uuid::new_v4().to_string(),
                    format: Some(self.claim_format.name()),
                    restrictions: vec![],
                },
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
                        audience: ISSUER_ID.to_string(),
                        issuer: None,
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
                    nonce: oid4vci::types::Nonce::new(nonce.secret().to_owned()),
                },
                controller: ProofOfPossessionController {
                    vm: Some(hld_did_url.to_owned()),
                    jwk: h_kh.jwk().unwrap(),
                },
            };

            let signing_input = pop.to_jwt_signing_input().unwrap();
            let signed = h_kh.sign(&signing_input).await.unwrap();

            pop.to_jwt_with_signature(signed).unwrap()
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

            SdJwtAPI::create_vc(claims.clone(), iss_data, hld_data, vc_meta)
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
            contexts: &[String],
            vc_types: &[String],
        ) -> json_ld_vc::VC {
            let vc_meta = json_ld_vc::VCMetadata::new(
                contexts
                    .iter()
                    .map(|s| IriRefBuf::from_str(s).unwrap())
                    .collect(),
                vc_types.to_owned(),
            )
            .unwrap();

            JsonLdAPI::create_vc(claims.clone(), iss_data, hld_data, vc_meta)
                .await
                .unwrap()
        }

        async fn json_ld_vp(
            vc: &json_ld_vc::VC,
            kh: impl KeyHandle,
            nonce: &Nonce,
        ) -> json_ld_vc::VP {
            let vp_meta = json_ld_vc::VPMetadata::new().unwrap();

            JsonLdAPI::create_vp(vc, kh, nonce, VERIFIER_ID, vp_meta)
                .await
                .unwrap()
        }
    }
}
