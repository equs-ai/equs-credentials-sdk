use crate::didcomm::core::message_receiver::MessageReceiver;
use crate::didcomm::transport::{
    AlreadyRunningSnafu, ConfigurationSnafu, DecodingSnafu, InboundTransport, NetworkSnafu,
    NotRunningSnafu, OutboundMessage, OutboundMessageResponse, OutboundTransport, Result,
    TransportType, UnsupportedTransportSnafu,
};
use crate::http::HttpClient;
use async_lock::{Mutex, RwLock};
use async_trait::async_trait;
use futures::channel::oneshot;
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Method, Request, Response, Server, StatusCode};
use snafu::ensure;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use tracing::{debug, error, info, instrument, warn};
use url::Url;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpTransportState {
    Stopped,
    Starting,
    Running,
    Stopping,
}

#[derive(Clone)]
pub struct HttpTransport {
    endpoint: Url,
    client: crate::reqwest::ReqwestClient,
    state: Arc<RwLock<HttpTransportState>>,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}

impl HttpTransport {
    pub fn new(endpoint: Url, client: crate::reqwest::ReqwestClient) -> Self {
        Self {
            endpoint,
            client,
            state: Arc::new(RwLock::new(HttpTransportState::Stopped)),
            shutdown_tx: Arc::new(Mutex::new(None)),
        }
    }

    fn parse_endpoint(&self) -> Result<SocketAddr> {
        let port = self.endpoint.port().unwrap_or_else(|| {
            if self.endpoint.scheme() == "https" {
                443
            } else {
                80
            }
        });

        // Get the host and port
        let host = self.endpoint.host_str().ok_or_else(|| {
            ConfigurationSnafu {
                details: "Missing host in endpoint URL".to_string(),
            }
            .build()
        })?;

        // Parse as socket address
        let socket_addr = format!("{}:{}", host, port);
        SocketAddr::from_str(&socket_addr).map_err(|e| {
            ConfigurationSnafu {
                details: format!("Invalid socket address: {}", e),
            }
            .build()
        })
    }

    async fn handle_request(
        &self,
        req: Request<Body>,
        message_receiver: &MessageReceiver,
    ) -> Result<Response<Body>> {
        debug!("Received request: {:?}", req);

        // Only accept POST requests
        if req.method() != Method::POST {
            let response = Response::builder()
                .status(StatusCode::METHOD_NOT_ALLOWED)
                .body(Body::from("Only POST requests are supported"))
                .unwrap();
            return Ok(response);
        }

        // Check content type
        let content_type = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("application/octet-stream");

        let body_bytes = hyper::body::to_bytes(req.into_body()).await.map_err(|e| {
            DecodingSnafu {
                details: e.to_string(),
            }
            .build()
        })?;

        let message_receiver = message_receiver.clone();
        tokio::task::spawn(async move {
            // Process the message
            let result = message_receiver.receive_message(&body_bytes).await;

            if let Err(e) = result {
                // TODO Send Problem Report
            }
        });

        let response = Response::builder()
            .status(StatusCode::ACCEPTED)
            .body(Body::empty())
            .unwrap();
        Ok(response)
    }
}

#[async_trait]
impl InboundTransport for HttpTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Http
    }

    #[instrument(skip(self, message_receiver))]
    async fn start(&self, message_receiver: MessageReceiver) -> Result<()> {
        // Check if the transport is already running
        {
            let state = *self.state.read().await;
            if state == HttpTransportState::Running || state == HttpTransportState::Starting {
                return AlreadyRunningSnafu.fail();
            }
        }

        // Set state to starting
        {
            let mut state = self.state.write().await;
            *state = HttpTransportState::Starting;
        }

        // Parse the endpoint
        let addr = self.parse_endpoint()?;

        let self_clone = self.clone();
        let make_svc = make_service_fn(move |_conn| {
            let self_clone = self_clone.clone();
            let message_receiver = message_receiver.clone();
            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    let self_clone = self_clone.clone();
                    let message_receiver = message_receiver.clone();
                    async move { self_clone.handle_request(req, &message_receiver).await }
                }))
            }
        });

        // Create a channel for shutdown signaling
        let (tx, rx) = oneshot::channel::<()>();

        // Store the sender
        {
            let mut shutdown_tx = self.shutdown_tx.lock().await;
            *shutdown_tx = Some(tx);
        }

        // Create and run the server
        let server = Server::bind(&addr).serve(make_svc);

        // Set up graceful shutdown
        let server_with_shutdown = server.with_graceful_shutdown(async {
            rx.await.ok();
            debug!("HTTP transport shutdown signal received");
        });

        // Set state to running
        {
            let mut state = self.state.write().await;
            *state = HttpTransportState::Running;
        }

        // Run the server in a separate task
        tokio::spawn(async move {
            info!("HTTP transport listening on {}", addr);

            if let Err(e) = server_with_shutdown.await {
                error!("HTTP transport error: {:?}", e);
            }

            info!("HTTP transport stopped");
        });

        Ok(())
    }

    #[instrument(skip(self))]
    async fn stop(&self) -> Result<()> {
        // Check if the transport is running
        {
            let state = *self.state.read().await;
            if state == HttpTransportState::Stopped || state == HttpTransportState::Stopping {
                return NotRunningSnafu.fail();
            }
        }

        // Set state to stopping
        {
            let mut state = self.state.write().await;
            *state = HttpTransportState::Stopping;
        }

        // Send shutdown signal
        let tx = {
            let mut shutdown_tx = self.shutdown_tx.lock().await;
            shutdown_tx.take()
        };

        if let Some(tx) = tx {
            if let Err(e) = tx.send(()) {
                warn!("Failed to send shutdown signal: {:?}", e);
            }
        }

        // Set state to stopped
        {
            let mut state = self.state.write().await;
            *state = HttpTransportState::Stopped;
        }

        Ok(())
    }

    async fn is_running(&self) -> bool {
        let state = *self.state.read().await;
        state == HttpTransportState::Running
    }

    fn endpoint(&self) -> &str {
        self.endpoint.as_str()
    }
}

#[async_trait]
impl OutboundTransport for HttpTransport {
    fn transport_type(&self) -> TransportType {
        TransportType::Http
    }

    #[instrument(skip(self, message), fields(endpoint = message.endpoint))]
    async fn send_message(&self, message: OutboundMessage) -> Result<OutboundMessageResponse> {
        let url = message.endpoint_url()?;

        ensure!(
            self.supports_scheme(&url),
            UnsupportedTransportSnafu {
                details: url.scheme().to_string(),
            }
        );

        // Create the request
        let request_builder = oauth2::http::Request::builder()
            .method(oauth2::http::Method::POST)
            .uri(message.endpoint)
            .header(oauth2::http::header::CONTENT_TYPE, message.content_type)
            .header(oauth2::http::header::ACCEPT, message.accept_content_type);

        // Create the request with the body
        let request = request_builder.body(message.payload).map_err(|e| {
            DecodingSnafu {
                details: e.to_string(),
            }
            .build()
        })?;

        debug!("Sending HTTP request to: {}", url);
        let response = self.client.async_call(request).await.map_err(|e| {
            NetworkSnafu {
                details: e.to_string(),
            }
            .build()
        })?;

        let status = response.status().as_u16();

        let mut headers = Vec::new();
        for (name, value) in response.headers() {
            if let Ok(value_str) = value.to_str() {
                headers.push((name.to_string(), value_str.to_string()));
            }
        }

        let body = if response.status().is_success() {
            Some(response.body().to_owned())
        } else {
            None
        };

        let message_response = OutboundMessageResponse {
            status,
            body,
            headers,
        };

        Ok(message_response)
    }

    fn supports_scheme(&self, url: &Url) -> bool {
        url.scheme() == "http" || url.scheme() == "https"
    }

    async fn start(&self) -> Result<()> {
        // No special initialization needed for outbound transport
        Ok(())
    }

    async fn stop(&self) -> Result<()> {
        // No special cleanup needed for outbound transport
        Ok(())
    }
}
