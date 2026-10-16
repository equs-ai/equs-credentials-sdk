# didcomm::transport — Context

## Purpose
Defines the transport layer abstractions (`InboundTransport`, `OutboundTransport`) and all supporting types. Concrete implementations live in sub-modules.

## Files

| File | Role |
|------|------|
| `mod.rs` | `InboundTransport` + `OutboundTransport` traits, `OutboundMessage`, `OutboundMessageResponse`, `TransportType`, `Error` |
| `http/` | `HttpTransport` — concrete HTTP inbound + outbound implementation — see [http/CLAUDE.md](http/CLAUDE.md) |
| `mock.rs` | Mock transport for tests (`#[cfg(test)]`) |

## Key types / traits

### `InboundTransport`
```
transport_type() → TransportType
start(message_receiver: MessageReceiver) → Result<()>
stop() → Result<()>
is_running() → bool
endpoint() → &str
```
`start` receives a `MessageReceiver` clone. The transport spawns its own async task and forwards raw bytes to `MessageReceiver::receive_message`.

### `OutboundTransport`
```
transport_type() → TransportType
send_message(message: OutboundMessage) → Result<OutboundMessageResponse>
supports_scheme(url: &Url) → bool
start() → Result<()>
stop() → Result<()>
```

### `OutboundMessage`
`{ endpoint: String, payload: Vec<u8>, content_type: String, accept_content_type: String }`
Has convenience method `endpoint_url() → Result<Url>`.

### `OutboundMessageResponse`
`{ status: u16, body: Option<Vec<u8>>, headers: Vec<(String, String)> }`

### `TransportType`
`Http | WebSocket | Custom(&'static str)` — implements `Display`.

## Error variants
`Url`, `Configuration { details }`, `UnsupportedTransport { details }`, `Network { details }`, `AlreadyRunning`, `NotRunning`, `Decoding { details }`.

## Dependencies
- Depends on: `crate::didcomm::core::message_receiver::MessageReceiver`
- Used by: `crate::didcomm::core::{DIDCommService, MessageSender}`, `crate::didcomm::agent::Agent`

## Constraints
- Non-wasm only.
- `didcomm-http-transport` feature flag must be enabled for the HTTP concrete implementation to compile.
