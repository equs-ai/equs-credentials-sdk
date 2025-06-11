pub mod common;
pub mod empty;
pub mod issuance;
pub mod problem_report;

#[cfg(test)]
mod tests {
    use url::Url;

    use crate::didcomm::agent::AgentConfig;
    use crate::didcomm::agent::test_utils::setup_agent;
    use crate::didcomm::protocol::aries::issuance::holder::Holder;
    use crate::didcomm::protocol::aries::issuance::holder::states::HolderState;
    use crate::didcomm::protocol::aries::issuance::issuer::Issuer;
    use crate::didcomm::protocol::aries::issuance::issuer::fixture::credential_info;
    use crate::didcomm::protocol::aries::issuance::issuer::states::IssuerState;
    use crate::didcomm::protocol::outofband::InvitationConfig;
    use crate::inmem::storage::InMemStorage;
    use crate::inmem::vault::InMemVault;
    use crate::kms::KeyType;
    use crate::utils::test_utils::create_did_and_key_metadata_by_key_type;

    #[tokio::test]
    async fn test_issuance() {
        let issuer_agent_config = AgentConfig {
            domain: Url::parse("http://government-agent.example.com").unwrap(),
            endpoint: Url::parse("http://127.0.0.1:8010").unwrap(),
            label: "Government Agent".to_string(),
            didcomm_scheme: Some("didcomm".to_string()),
        };

        let issuer_agent = setup_agent(issuer_agent_config.clone());
        issuer_agent.start().await.unwrap();

        println!("Issuer Agent started at {}", issuer_agent_config.endpoint);

        let issuer = Issuer::new(
            &issuer_agent,
            InMemStorage::<String, IssuerState>::new(),
            KeyType::P256,
        )
        .await
        .unwrap();

        println!("1. Issuer creates a credential offer");
        let credential_info = credential_info(issuer_agent.kms()).await;
        let thread_id = issuer.create_offer(credential_info).await.unwrap();

        let (iss_subscription, iss_observable) = issuer.observe_state(thread_id.to_owned()).await;

        let issuer_state = issuer.get_state(&thread_id).await.unwrap();
        assert!(matches!(issuer_state, IssuerState::Initial(_)));
        if let IssuerState::Initial(state) = issuer_state {
            println!("{}", serde_json::to_string_pretty(&state.offer).unwrap());
        }
        println!("===============================================================================");

        println!("2. Issuer creates an invitation");
        let invitation_config = InvitationConfig {
            key_type: KeyType::P256,
            label: "Issuer's Invitation".to_string(),
            goal: "Credential Offer".to_string(),
            goal_code: "offer-credential".to_string(),
            attachments: vec![],
        };

        let invitation_url = issuer
            .create_invitation(&thread_id, invitation_config)
            .await
            .unwrap();

        let issuer_state = iss_observable.next().await.unwrap();
        println!("{invitation_url}");
        assert!(matches!(issuer_state, IssuerState::OfferSent(_)));
        println!("===============================================================================");

        let holder_config = AgentConfig {
            domain: Url::parse("http://alice-agent.example.com").unwrap(),
            endpoint: Url::parse("http://127.0.0.1:8020").unwrap(),
            label: "Alice Agent".to_string(),
            didcomm_scheme: Some("didcomm".to_string()),
        };

        let holder_agent = setup_agent(holder_config.clone());
        holder_agent.start().await.unwrap();

        println!("Holder Agent started at {}", holder_config.endpoint);

        let (hld_did, hld_key_metadata) =
            create_did_and_key_metadata_by_key_type(holder_agent.kms(), KeyType::P256).await;

        println!("3. Holder accepts the invitation");

        let mut holder = Holder::new(
            invitation_url,
            hld_key_metadata,
            &holder_agent,
            InMemStorage::<String, HolderState>::new(),
            InMemVault::new(),
            KeyType::P256,
        )
        .await
        .unwrap();
        println!("===============================================================================");

        let (hld_subscription, hls_observable) = holder.observe_state().await;

        println!("4. Holder sends credential request");
        holder.send_request().await.unwrap();

        let holder_state = hls_observable.next().await.unwrap();
        assert!(matches!(holder_state, HolderState::RequestSent(_)));
        println!("===============================================================================");

        let issuer_state = iss_observable.next().await.unwrap();
        println!("5. Issuer received credential request");
        assert!(matches!(issuer_state, IssuerState::RequestReceived(_)));
        if let IssuerState::RequestReceived(state) = issuer_state {
            println!("{}", serde_json::to_string_pretty(&state.request).unwrap());
        }
        println!("===============================================================================");

        println!("6. Issuer sends credential");
        issuer.send_credential(&thread_id).await.unwrap();

        let issuer_state = iss_observable.next().await.unwrap();
        assert!(matches!(issuer_state, IssuerState::CredentialSent(_)));
        println!("===============================================================================");

        let holder_state = hls_observable.next().await.unwrap();
        println!("7. Holder received credential");
        assert!(matches!(holder_state, HolderState::Finished(_)));
        if let HolderState::Finished(state) = holder_state {
            println!(
                "{}",
                serde_json::to_string_pretty(&state.credential).unwrap()
            );
        }
        println!("===============================================================================");

        let issuer_state = iss_observable.next().await.unwrap();
        println!("8. Issuer received acknowledgement");
        assert!(matches!(issuer_state, IssuerState::Finished(_)));
        println!("===============================================================================");

        issuer_agent.stop().await.unwrap();
        holder_agent.stop().await.unwrap();
    }
}
