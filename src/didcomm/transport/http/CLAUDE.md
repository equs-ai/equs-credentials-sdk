# didcomm::transport::http — Context

## Purpose
Concrete HTTP implementation of both `InboundTransport` and `OutboundTransport` using `hyper` (server side) and `crate::reqwest::ReqwestClient` (client side).

## Files

| File | Role |
|------|------|
| `mod.rs` | `HttpTransport` struct, both transport trait impls, state machine, error mapping |

## Key types / traits

### `HttpTransport`
```
pub struct HttpTransport {
    endpoint: Url,
    client: crate::reqwest::ReqwestClient,
    state: Arc<RwLock<HttpTransportState>>,
    shutdown_tx: Arc<Mutex<Option<oneshot::Sender<()>>>>,
}
```
Created via `HttpTransport::new(endpoint, client)`.

### State machine (`HttpTransportState`)
`Stopped → Starting → Running → Stopping → Stopped`. Guards against double-start (`AlreadyRunning`) and stop-when-not-running (`NotRunning`).

### Inbound (`InboundTransport` impl)
- `start(message_receiver)`: binds a `hyper::Server` to the parsed socket address.
  - Only `POST` requests accepted; all others return `405 Method Not Allowed`.
  - Body forwarded to `MessageReceiver::receive_message` in a `tokio::spawn` task.
  - Responds immediately with `202 Accepted` (fire-and-forget).
  - Graceful shutdown via `oneshot::channel` stored in `shutdown_tx`.
- `stop()`: sends shutdown signal, transitions state to `Stopped`.

### Outbound (`OutboundTransport` impl)
- `send_message(message)`: POST via `self.client.async_call(request)`.
- `supports_scheme(url)`: `http` or `https` only.
- `start()` / `stop()`: no-ops.

## Dependencies
- Depends on: `hyper`, `tokio::sync::oneshot`, `crate::reqwest::ReqwestClient`, `crate::didcomm::core::message_receiver::MessageReceiver`, `super::transport::{InboundTransport, OutboundTransport, OutboundMessage, OutboundMessageResponse}`
- Used by: `DIDCommService` when wiring inbound + outbound HTTP endpoints

## Constraints
- Feature-gated: only compiled when `didcomm-http-transport` feature is enabled.
- Non-wasm only.
- When `receive_message` returns `Err`, the error is silently dropped (TODO: send Problem Report).
