pub(crate) mod api;
mod holder;
mod issuer;
mod verifier;

pub use holder::HolderService;
pub use issuer::IssuerService;
pub use verifier::VerifierService;

pub use api::*;

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::str::FromStr;

    use oid4vci::openidconnect::Nonce;
    use serde_json::json;
    use ssi::did::DIDURL;

    use crate::crypto::{Alg, Key};
    use crate::did::didkey::DIDKey;
    use crate::inmem::kms::LocalKms;
    use crate::inmem::vault::InMemVault;
    use crate::kms::Kms;
    use crate::vc::core::holder::HolderService;
    use crate::vc::core::issuer::IssuerService;
    use crate::vc::core::verifier::VerifierService;
    use crate::vc::core::{
        CredentialDefinition, CredentialDefinitionData, Holder, HolderMetadata, Issuer,
        IssuerMetadata, KeyMetadata, PresentationInput, Verifier,
    };
    use crate::vc::pop;
    use crate::{kms, vc};

    #[tokio::test]
    async fn e2e() {
        // Initialization
        let issuer = issuer().await;
        let holder = holder().await;
        let verifier = verifier("ver-id");

        println!("Issue credential...");

        let offer = issuer.offer_credential("SD_JWT_cred", None);
        assert!(offer.is_ok());
        let offer = offer.unwrap();

        let nonce = Nonce::new_random();
        let request = holder.request_credential(&offer, nonce.secret()).await;
        assert!(request.is_ok());
        let request = request.unwrap();

        let claims = json!( {
            "given_name": "John",
            "family_name": "Doe",
            "dob": "09/09/1989",
        });
        let cl = claims.as_object().unwrap().clone();
        println!("Claims: {:?}", cl);

        let vc_res = issuer
            .issue_credential(&request, &claims, nonce.secret())
            .await;
        assert!(vc_res.is_ok());

        let (vc, vc_meta) = vc_res.unwrap();
        println!("Credential {:?}", &vc);

        let store_res = holder.store_credential(&vc, &vc_meta).await;
        assert!(store_res.is_ok());

        println!("Present proof...");

        let presentation_input = PresentationInput {
            id: "SD_JWT_cred".into(),
            type_: "https://credentials.example.com/identity_credential".to_string(),
            format: "vc+sd-jwt".into(),
            claims: json!({
               "given_name": true,
               "family_name": true,
            })
            .as_object()
            .unwrap()
            .to_owned(),
        };

        let nonce = Nonce::new_random();

        let vp_res = holder
            .create_presentation_auto(nonce.secret(), "ver-id", &presentation_input)
            .await;
        assert!(vp_res.is_ok());

        let vp = vp_res.unwrap();
        println!("Presentation {:?}", vp);

        let ver_res = verifier.verify_presentation(nonce.secret(), &vp).await;
        assert!(ver_res.is_ok());

        let res_claims = ver_res.unwrap();
        println!("Presentation claims {:?}", res_claims);

        assert!(res_claims.as_object().unwrap().contains_key("given_name"));
        assert!(res_claims.as_object().unwrap().contains_key("family_name"));
        // should return not only requested claims, but all in credential
        assert!(res_claims.as_object().unwrap().contains_key("dob"));
    }

    async fn issuer() -> impl Issuer {
        // Initialization
        println!("Issuer creating...");

        let kms = LocalKms::new();
        let didkey = DIDKey::new();

        let kt = kms::KeyType::P256;
        let (kid, kh) = kms
            .create_and_handle(kt, kms::CreateOptions {})
            .await
            .unwrap();

        let did = didkey.generate(kh.clone()).unwrap();
        let did_url = DIDURL::from_str(&did).unwrap();
        println!("DID: {}", did);

        let jwk = kh.clone().jwk().unwrap();
        println!("Key JWK:\n{}", serde_json::to_string_pretty(&jwk).unwrap());

        let metadata = IssuerMetadata {
            issuer_id: did_url.to_string(),
            cred_defs: vec![CredentialDefinition {
                cred_def_id: "SD_JWT_cred".into(),
                format: vc::VCFormat::SdJwtVc,
                claims: Default::default(),
                supported_proofs: Some(HashMap::from([(pop::Format::Jwt, vec![Alg::ES256])])),
                supported_signing_algs: Some(vec![Alg::ES256]),
                display: None,
                protocol_data: Some(CredentialDefinitionData::SdJwt {
                    vct: "https://credentials.example.com/identity_credential".to_owned(),
                    disclosures: vec!["$.given_name".to_owned(), "$.family_name".to_owned()],
                    lifetime: None,
                }),
                key_metadata: KeyMetadata {
                    did_url: did_url.to_string(),
                    kid: kid.clone(),
                },
            }],
            protocol_data: None,
        };

        IssuerService::new(kms, metadata)
    }

    async fn holder() -> impl Holder {
        // Initialization
        println!("Holder creating...");

        let kms = LocalKms::new();
        let didkey = DIDKey::new();
        let vault = InMemVault::new();

        let kt = kms::KeyType::P256;
        let (kid, kh) = kms
            .create_and_handle(kt, kms::CreateOptions {})
            .await
            .unwrap();

        let did = didkey.generate(kh.clone()).unwrap();
        let did_url = DIDURL::from_str(&did).unwrap();
        println!("DID: {}", did);

        let jwk = kh.clone().jwk().unwrap();
        println!("Key JWK:\n{}", serde_json::to_string_pretty(&jwk).unwrap());

        HolderService::new(
            kms,
            vault,
            HolderMetadata {
                client_id: "client_id".into(),
                key_metadata: KeyMetadata {
                    did_url: did_url.to_string(),
                    kid: kid.clone(),
                },
            },
        )
    }

    fn verifier(id: &str) -> impl Verifier {
        VerifierService::new(id)
    }
}
