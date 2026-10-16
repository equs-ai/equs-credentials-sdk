use crate::did::universal::UniversalResolver;
use crate::didcomm::core::envelope::{EnvelopeService, Message, UnpackOptions};
use crate::didcomm::core::message_receiver::MessageReceiver;
use crate::didcomm::transport;
use crate::didcomm::transport::{
    InboundTransport, OutboundMessage, OutboundMessageResponse, OutboundTransport, TransportType,
};
use crate::inmem::kms::LocalKms;
use async_lock::RwLock;
use async_trait::async_trait;
use std::sync::Arc;
use url::Url;

#[derive(Clone)]
pub struct MockTransport {
    endpoint: Url,
    is_running: Arc<RwLock<bool>>,
    outbound_messages: Arc<RwLock<Vec<Message>>>,
    envelope_service: EnvelopeService,
}

impl MockTransport {
    pub fn new(endpoint: Url, kms: &LocalKms, resolver: &UniversalResolver) -> Self {
        let envelope_service = EnvelopeService::new(kms.clone(), resolver.clone());

        MockTransport {
            endpoint,
            is_running: Default::default(),
            outbound_messages: Default::default(),
            envelope_service: EnvelopeService::new(kms.clone(), resolver.clone()),
        }
    }

    pub async fn next_message<T: TryFrom<didcomm::Message, Error = serde_json::Error>>(&self) -> T {
        self.outbound_messages
            .write()
            .await
            .pop()
            .unwrap()
            .try_into()
            .unwrap()
    }
}

#[async_trait]
impl OutboundTransport for MockTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Http
    }

    async fn send_message(
        &self,
        message: OutboundMessage,
    ) -> transport::Result<OutboundMessageResponse> {
        let message_str = String::from_utf8_lossy(&message.payload);
        let (message, _) = self
            .envelope_service
            .unpack(message_str.as_ref(), &UnpackOptions::default())
            .await
            .unwrap();

        self.outbound_messages.write().await.push(message);

        Ok(OutboundMessageResponse {
            status: 200,
            body: None,
            headers: vec![],
        })
    }

    fn supports_scheme(&self, url: &Url) -> bool {
        url.scheme() == "http" || url.scheme() == "https"
    }

    async fn start(&self) -> transport::Result<()> {
        Ok(())
    }

    async fn stop(&self) -> transport::Result<()> {
        Ok(())
    }
}

#[async_trait]
impl InboundTransport for MockTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Http
    }

    async fn start(&self, message_receiver: MessageReceiver) -> transport::Result<()> {
        *self.is_running.write().await = true;

        Ok(())
    }

    async fn stop(&self) -> transport::Result<()> {
        *self.is_running.write().await = false;

        Ok(())
    }

    async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }

    fn endpoint(&self) -> &str {
        self.endpoint.as_str()
    }
}
