#[cfg(test)]
pub mod test_utils;

use common_macros::DebugError;
use snafu::{Location, ResultExt, Snafu};
use std::marker::PhantomData;
use url::Url;

use crate::did::universal::UniversalResolver;
use crate::didcomm::connection::ConnectionService;
use crate::didcomm::core::dispatcher::DispatcherService;
use crate::didcomm::core::envelope::{DIDCommKms, EnvelopeService, Message};
use crate::didcomm::core::event_emitter::EventEmitter;
use crate::didcomm::core::message_receiver::{MessageReceiver, MessageReceiverConfig};
use crate::didcomm::core::message_sender::{MessageSender, SendOptions};
use crate::didcomm::core::protocol::Protocol;
use crate::didcomm::core::protocol_registry::ProtocolRegistry;
use crate::didcomm::core::{message_sender, protocol_registry};
use crate::didcomm::service::DIDCommService;
use crate::didcomm::transport::{InboundTransport, OutboundTransport};
use crate::didcomm::{connection, service};
use crate::kms::{KeyHandle, Kms};

#[derive(Snafu, DebugError)]
#[non_exhaustive]
pub enum Error {
    #[snafu(display("DIDComm service error"))]
    DIDComm {
        source: service::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Protocol Registry error"))]
    ProtocolRegistry {
        source: protocol_registry::Error,
        #[snafu(implicit)]
        location: Location,
    },
    #[snafu(display("Connection error"))]
    Connection {
        source: connection::Error,
        #[snafu(implicit)]
        location: Location,
    },
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct AgentConfig {
    pub didcomm_scheme: Option<String>,
    pub domain: Url,
    pub endpoint: Url,
    pub label: String,
}

#[derive(Clone)]
pub struct Agent<KMS, KH, C>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
    C: ConnectionService + Clone,
{
    config: AgentConfig,
    kms: KMS,
    did_resolver: UniversalResolver,
    didcomm_service: DIDCommService,
    protocol_registry: ProtocolRegistry,
    connection_service: C,
    _phantom: PhantomData<KH>,
}

impl<KMS, KH, C> Agent<KMS, KH, C>
where
    KMS: DIDCommKms<KH> + Clone + 'static,
    KH: KeyHandle + 'static,
    C: ConnectionService + Clone + 'static,
{
    pub fn new(
        //TODO: Enable builder
        config: AgentConfig,
        kms: KMS,
        did_resolver: UniversalResolver,
        connection_service: C,
        inbound_transport: impl InboundTransport + Clone + 'static,
        outbound_transport: impl OutboundTransport + Clone + 'static,
    ) -> Self {
        let envelope_service = EnvelopeService::new(kms.clone(), did_resolver.clone());

        let protocol_registry = ProtocolRegistry::new();

        let dispatcher = DispatcherService::new(protocol_registry.clone());

        let message_receiver = MessageReceiver::new(
            envelope_service.clone(),
            dispatcher,
            MessageReceiverConfig::default(),
        );

        let message_sender = MessageSender::new(
            envelope_service,
            outbound_transport.clone(),
            EventEmitter::<&'static str, message_sender::Event>::new(),
            did_resolver.clone(),
        );

        let didcomm_service = DIDCommService::new(
            message_receiver,
            message_sender,
            inbound_transport,
            outbound_transport,
        );

        Self {
            config,
            kms,
            did_resolver,
            didcomm_service,
            protocol_registry,
            connection_service,
            _phantom: PhantomData,
        }
    }
}

impl<KMS, KH, C> Agent<KMS, KH, C>
where
    KMS: Kms<KH> + Clone,
    KH: KeyHandle,
    C: ConnectionService + Clone,
{
    pub async fn start(&self) -> Result<()> {
        self.didcomm_service
            .initialize()
            .await
            .context(DIDCommSnafu)
    }

    pub async fn stop(&self) -> Result<()> {
        self.didcomm_service.shutdown().await.context(DIDCommSnafu)
    }

    pub async fn register_protocol(&self, protocol: impl Protocol + 'static) -> Result<()> {
        self.protocol_registry
            .register_protocol(protocol)
            .await
            .context(ProtocolRegistrySnafu)
    }

    pub async fn send_message(&self, msg: &mut Message, connection_id: &str) -> Result<()> {
        let connection = self
            .connection_service
            .get_connection(connection_id)
            .await
            .context(ConnectionSnafu)?;

        let from_did = connection.my_did.to_owned();
        let to_did = connection.their_did().context(ConnectionSnafu)?;

        msg.from = Some(from_did.clone());
        msg.to = Some(vec![to_did.clone()]);

        self.didcomm_service
            .send_message(
                msg,
                to_did,
                &SendOptions {
                    from: Some(&from_did),
                    sign_by: None,
                },
            )
            .await
            .context(DIDCommSnafu)
    }

    pub fn kms(&self) -> &KMS {
        &self.kms
    }

    pub fn didcomm_service(&self) -> &DIDCommService {
        &self.didcomm_service
    }

    pub fn did_resolver(&self) -> &UniversalResolver {
        &self.did_resolver
    }

    pub fn configuration(&self) -> &AgentConfig {
        &self.config
    }

    pub fn connection_service(&self) -> &C {
        &self.connection_service
    }
}
