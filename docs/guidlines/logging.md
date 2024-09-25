# Overview

`agent-sdk` uses `tracing` crate to log events for each execution flow of sdk.

One of the reasons for using the `tracing` crate is that it solves the problem of intermixing of logs in `async` libraries like `agent-sdk`.

## Rules

Each developer must follow these rules when adding the new features into codebase of `agent-sdk`

### General

 - Use `#[instrument]` attribute macro for logging the entrance and exiting events of methods / functions
 - Disable logging of `&self/&mut self` in methods by declaring `skip` property like `#[instrument(skip(self))]`
 - To avoid long or unclear function / method names, use `name` property like `#[instrument(name = "Issuer service init")]`
 - To log `return` values of function / method, use the `ret` property like `#[instrument(ret())]`
    * If `return` value implements `Display` trait, use `#[instrument(ret(Display))]`
 - To log `error` events of function / method, use the `ret` property like `#[instrument(err())]`


### Error level

`error!()` macro from `tracing::error` will be used for logging when:

- Returning the `error` of the function:
   ```rust
    #[instrument(err())]
    async fn issue_credential(&self, ...) -> Result<.., Error> {}
  ```
- Showing useful errors within the function:
   ```rust
    error!(?nonce_request_err);
   ```

### Info level

`info!()` macro from `tracing::info` will be used for logging when:

- The completion of flows:
   ```rust
   info!("offer is created");
   info!("issuance is failed");
   ```
- The saving or finding of internal states:
   ```rust
   info!("nonce is saved");
   ```
- The initialization of `agent-sdk` components:
   ```rust
   info!("Issuer Service is initialized");
   ```
 
### Debug level

`debug!()` macro from `tracing::debug` will be used for logging when:

- Showing some useful variables/outcomes(end-user insensitive) within the function:
   ```rust
    debug!(?supported_cred_config_ids);
   ```


### Trace level

`trace!()` macro from `tracing::trace` will be used for logging when:

- Showing the entrance of the internal functions / methods:
   ```rust
    #[instrument(level = Level::TRACE)]
    fn resolve_cred_def_id(&self, req: &CredentialRequest) {}
   ```
- Function / Method arguments including the end-user sensitive:
   ```rust
    #[instrument(level = Level::TRACE, skip(self))]
    pub async fn issue_credential(&self, cred_request: &CredentialRequest, token: &str, nonce: Nonce, claims: &Value) {}
   ```
- Returning the result of the function:
   ```rust
    #[instrument(ret())]
    async fn issue_credential(&self, ...) -> Result<CredentialResponse> {}
   ```
- Showing the end-user sensitive or the secret data:
   ```rust
    trace!(?auth_server_admin_auth_header);
    trace!(?claims);
   ```

### Logging of sensitive data

For debug purposes it's allowed to log sensitive values with `trace` and `debug` levels.
Release builds will not reveal any logs with level less that `warn` since there is an option
in `Cargo.toml` that [blocks it](https://docs.rs/tracing/latest/tracing/level_filters/index.html):

```
tracing = { version = "0.1.40", features = ["attributes", "release_max_level_warn"] }
```


## Consuming logs

On the application side, to collect logs from `agent-sdk`, follow the steps below:

1. Add `tracing-subscriber` dependency into `Cargo.toml`:
  ```toml
    tracing-subscriber = "0.3.18"
  ```
2. Add the following to your executable to initialize the default subscriber:
```rust
use tracing_subscriber;

async fn main() {
    tracing_subscriber::fmt::init();
}
```
3. For example, to see `TRACE` level logs, run:
```shell
RUST_LOG=TRACE cargo run
```