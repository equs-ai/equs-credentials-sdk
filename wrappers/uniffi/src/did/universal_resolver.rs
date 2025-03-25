use agent_sdk::did::universal::UniversalResolver;
use agent_sdk::did::{DIDBuf, DIDResolver};
use std::str::FromStr;

use crate::common::{Error, Result};
use crate::did::{DIDResolution, VerificationMethod};

/// An Universal `DID` resolver.
///
/// # Supported methods
///
/// `did:key`
/// `did:peer`
/// `did:web`
#[derive(uniffi::Object)]
pub struct UniversalDIDResolver(UniversalResolver);

#[uniffi::export]
impl UniversalDIDResolver {
    /// Creates a new Universal `DID` resolver.
    #[uniffi::constructor]
    pub fn new() -> UniversalDIDResolver {
        let resolver = UniversalResolver::default();

        UniversalDIDResolver(resolver)
    }

    /// Resolves a DID and extracts one of the verification methods it defines.
    ///
    /// This will return the first verification method found, although users
    /// should not expect the DID documents to always list verification methods
    /// in the same order.
    pub async fn resolve_verification_method(
        &self,
        did: String,
    ) -> Result<Option<VerificationMethod>> {
        let did = DIDBuf::from_str(&did).map_err(|err| Error::DIDResolution {
            details: format!("{err:?}"),
        })?;

        self.0
            .resolve_into_any_verification_method(&did)
            .await
            .map_err(|err| Error::DIDResolution {
                details: format!("{err:?}"),
            })?
            .map(|vm| vm.try_into())
            .transpose()
    }

    /// Resolves a DID.
    ///
    /// Fetches the DID document referenced by the input DID.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-resolution>
    pub async fn resolve(&self, did: String) -> Result<DIDResolution> {
        let did = DIDBuf::from_str(&did).map_err(|err| Error::DIDResolution {
            details: format!("{err:?}"),
        })?;

        self.0
            .resolve(&did)
            .await
            .map_err(|err| Error::DIDResolution {
                details: format!("{err:?}"),
            })
            .and_then(TryInto::try_into)
    }
}
