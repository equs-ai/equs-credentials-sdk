use crate::common::{Error, JsonValue, Result};
use crate::did::universal_resolver::UniversalDIDResolver;
use crate::key_handle::WrappedKeyHandle;
use crate::kms::{Kms, WrappedKms};
use crate::vc::Credential;
use agent_sdk::vc::core::{
    CredentialSigner as CoreCredentialSigner, SignCredential, UnsignedCredential,
};
use std::sync::Arc;

/// An async low-level `SignCredential` API.
///
/// Carries only what the signing step needs — a `Kms` for key access and a
/// DID resolver for LDP proof assembly. Use when the prepare/sign split is
/// driven from application code and a full issuer service is not desired.
#[derive(uniffi::Object)]
pub struct VCCoreCredentialSigner(Box<dyn SignCredential>);

#[uniffi::export(async_runtime = "tokio")]
impl VCCoreCredentialSigner {
    /// Create a new credential signer.
    #[uniffi::constructor]
    pub fn new(kms: Arc<dyn Kms>, did_resolver: Arc<UniversalDIDResolver>) -> Self {
        let signer: CoreCredentialSigner<WrappedKeyHandle, WrappedKms> =
            CoreCredentialSigner::new(WrappedKms::new(kms), did_resolver.inner());
        Self(Box::new(signer))
    }

    /// Sign an unsigned credential and return the finished `Credential`.
    ///
    /// The `unsigned_credential` argument is the externally-tagged JSON shape of
    /// the SDK's `UnsignedCredential` enum — `{ "SdJwt": { ... } }` or
    /// `{ "Ldp": { ... } }`.
    pub async fn sign_credential(&self, unsigned_credential: JsonValue) -> Result<Credential> {
        let unsigned: UnsignedCredential = serde_json::from_value(unsigned_credential)
            .map_err(|err| Error::OID4VCIInternal(format!("invalid UnsignedCredential: {err}")))?;
        self.0
            .sign_credential(unsigned)
            .await
            .map_err(|err| Error::OID4VCIInternal(format!("{err}")))
    }
}
