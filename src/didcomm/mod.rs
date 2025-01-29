use crate::did::DIDResolver;
use crate::didcomm::did_resolver::DidResolverWrapper;
use crate::didcomm::kms::KmsWrapper;
use crate::kms::{DerivativeKms, ECDH1PUParams, ECDHESParams, KeyHandle, Kms};
use common_macros::DebugError;
use snafu::{Location, ResultExt, Snafu};
use ssi::jwk::JWKResolver;
use std::marker::PhantomData;
use tracing::{instrument, Level};

mod did_resolver;
mod kms;

pub type AuthCryptAlg = didcomm::algorithms::AuthCryptAlg;
pub type Attachment = didcomm::Attachment;
pub type AttachmentBuilder = didcomm::AttachmentBuilder;
pub type Message = didcomm::Message;
pub type MessageBuilder = didcomm::MessageBuilder;
pub type PackEncryptedOptions = didcomm::PackEncryptedOptions;
pub type PackEncryptedMetadata = didcomm::PackEncryptedMetadata;
pub type PackSignedMetadata = didcomm::PackSignedMetadata;
pub type UnpackOptions = didcomm::UnpackOptions;
pub type UnpackMetadata = didcomm::UnpackMetadata;

#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[snafu(display("DIDComm error"))]
pub struct Error {
    source: didcomm::error::Error,
    #[snafu(implicit)]
    location: Location,
}

pub type Result<T> = std::result::Result<T, Error>;

/// A DIDComm service that provides packing and unpacking of DIDComm messages.
struct DIDCommService<D, R, KMS, KH>
where
    D: DIDResolver,
    R: JWKResolver,
    KMS: Kms<KH>
        + DerivativeKms<ECDH1PUParams, Output = Vec<u8>>
        + DerivativeKms<ECDHESParams, Output = Vec<u8>>,
    KH: KeyHandle,
{
    kms: KmsWrapper<KMS, KH, R>,
    did_resolver: DidResolverWrapper<D>,
    _phantom: PhantomData<KH>,
}

impl<D, R, KMS, KH> DIDCommService<D, R, KMS, KH>
where
    D: DIDResolver,
    R: JWKResolver,
    KMS: Kms<KH>
        + DerivativeKms<ECDH1PUParams, Output = Vec<u8>>
        + DerivativeKms<ECDHESParams, Output = Vec<u8>>,
    KH: KeyHandle,
{
    /// Creates a new [`DIDCommService`].
    ///
    /// # Arguments
    ///
    /// * `kms` - the key management system instance, providing cryptographic operations.
    /// * `did_resolver` - the resolver used to fetch DID documents.
    /// * `jwk_resolver` - the resolver used to fetch JWK keys by Verification Method ID.
    ///
    /// # Returns
    ///
    /// A new instance of [`DIDCommService`].
    #[instrument(level = Level::TRACE, skip_all)]
    pub fn new(kms: KMS, did_resolver: D, jwk_resolver: R) -> Self {
        DIDCommService {
            kms: KmsWrapper::new(kms, jwk_resolver),
            did_resolver: DidResolverWrapper::new(did_resolver),
            _phantom: PhantomData,
        }
    }

    /// Packs a plaintext DIDComm message without any signing or encryption.
    ///
    /// # Arguments
    ///
    /// * `message` - the [`Message`] to be packed.
    ///
    /// # Returns
    ///
    /// * The resulting plaintext message
    ///
    /// # Errors
    ///
    /// * [Error] an error if the packing process fails.
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    pub async fn pack_plaintext(&self, message: &Message) -> Result<String> {
        message
            .pack_plaintext(&self.did_resolver)
            .await
            .context(Snafu)
    }

    /// Packs a DIDComm message with a digital signature from the sender.
    ///
    /// The message will remain unencrypted, but signed by the specified key reference.
    ///
    /// # Arguments
    ///
    /// * `message` - the [`Message`] to be signed.
    /// * `sign_by` - a DID or key ID the sender uses for signing
    ///
    /// # Returns
    ///
    /// *  The signed message (serialized) and metadata
    ///
    /// # Errors
    ///
    /// * [Error] An error if the packing process fails.
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    pub async fn pack_signed(
        &self,
        message: &Message,
        sign_by: &str,
    ) -> Result<(String, PackSignedMetadata)> {
        message
            .pack_signed(sign_by, &self.did_resolver, &self.kms)
            .await
            .context(Snafu)
    }

    /// Packs a DIDComm message with optional signing, then encrypts it for the specified recipient.
    ///
    /// # Arguments
    ///
    /// * `message` - the [`Message`] to be encrypted.
    /// * `to` - recipient DID or key ID the sender uses encryption.
    /// * `from` - a sender DID or key ID. If set message will be repudiable authenticated or anonymous otherwise.
    ///    Must match `from` header in Plaintext if the header is set.
    /// * `sign_by` - if `Some` message will be additionally signed to provide additional non-repudiable authentication
    ///    by provided DID/Key. Signed messages are only necessary when the origin of plaintext must be provable
    ///    to third parties, or when the sender can’t be proven to the recipient by authenticated encryption because
    ///    the recipient is not known in advance (e.g., in a broadcast scenario).
    ///    Adding a signature when one is not needed can degrade rather than enhance security because
    ///    it relinquishes the sender’s ability to speak off the record.
    /// * `options` - allow fine configuration of packing process and have implemented `Default`.
    ///
    /// # Returns
    ///
    /// * The encrypted message and metadata
    ///
    /// # Errors
    ///
    /// * [Error] An error if the packing process fails.
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    pub async fn pack_encrypted(
        &self,
        message: &Message,
        to: &str,
        from: Option<&str>,
        sign_by: Option<&str>,
        options: &PackEncryptedOptions,
    ) -> Result<(String, PackEncryptedMetadata)> {
        message
            .pack_encrypted(to, from, sign_by, &self.did_resolver, &self.kms, options)
            .await
            .context(Snafu)
    }

    /// Unpacks a DIDComm message, optionally decrypting and verifying signatures.
    ///
    /// # Arguments
    ///
    /// * `msg` - the message as JSON string to be unpacked
    /// * `options` - allow fine configuration of unpacking process and imposing additional restrictions to message to be trusted.
    ///
    /// # Returns
    ///
    /// * The unpacked [`Message`] and metadata
    ///
    /// # Errors
    ///
    /// * [Error] An error if the unpacking process fails.
    #[instrument(level = Level::TRACE, skip(self), err(), ret())]
    pub async fn unpack(
        &self,
        msg: &str,
        options: &UnpackOptions,
    ) -> Result<(Message, UnpackMetadata)> {
        Message::unpack(msg, &self.did_resolver, &self.kms, options)
            .await
            .context(Snafu)
    }
}

#[cfg(test)]
mod test {
    use crate::did::didpeer::{DIDPeer, VerificationMethodKey, VerificationRelationshipType};
    use crate::did::universal::UniversalResolver;
    use crate::did::{DIDResolver, DID};
    use crate::didcomm::{DIDCommService, Message, UnpackOptions};
    use crate::inmem::kms::LocalKms;
    use crate::kms;
    use crate::kms::{KeyType, Kms};
    use crate::vc::core::KeyMetadata;
    use serde_json::json;

    #[tokio::test]
    async fn test_didcomm_pack_encrypted() {
        let kms = LocalKms::new();
        let (sender_did, sender_key_metadata) =
            create_did_and_key_metadata_by_key_type(&kms, KeyType::P256).await;
        let (recipient_did, recipient_key_metadata) =
            create_did_and_key_metadata_by_key_type(&kms, KeyType::P256).await;

        let msg = Message::build(
            sender_did.to_owned(),
            recipient_did.to_owned(),
            json!("example-body"),
        )
        .to(recipient_did.to_owned())
        .from(sender_did.to_owned())
        .finalize();

        let did_resolver = UniversalResolver::default();
        let didcomm_service = DIDCommService::new(kms, did_resolver.clone(), did_resolver);

        let encryption_options = didcomm::PackEncryptedOptions {
            protect_sender: true,
            ..Default::default()
        };

        let (packed_msg, metadata) = didcomm_service
            .pack_encrypted(
                &msg,
                &recipient_did,
                Some(&sender_did),
                None,
                &encryption_options,
            )
            .await
            .unwrap();

        let (msg, metadata) = didcomm_service
            .unpack(&packed_msg, &UnpackOptions::default())
            .await
            .unwrap();

        assert!(metadata.encrypted);
        assert!(metadata.authenticated);
        assert!(metadata.encrypted_from_kid.is_some());
        assert!(metadata
            .encrypted_from_kid
            .unwrap()
            .starts_with(&sender_did));

        assert_eq!(msg.from, Some(sender_did));
        assert_eq!(msg.to, Some(vec![recipient_did]));
        assert_eq!(msg.body, json!("example-body"));
    }

    #[tokio::test]
    async fn test_didcomm_pack_signed() {
        let kms = LocalKms::new();
        let did_resolver = UniversalResolver::default();

        let (sender_did, sender_key_metadata) =
            create_did_and_key_metadata_by_key_type(&kms, KeyType::P256).await;

        let msg = Message::build(
            sender_did.to_owned(),
            "http://example.com/protocols/lets_do_lunch/1.0/proposal".to_owned(),
            json!({}),
        )
        .finalize();

        let didcomm_service = DIDCommService::new(kms.clone(), did_resolver.clone(), did_resolver);

        let (signed_msg, _) = didcomm_service
            .pack_signed(&msg, &sender_did)
            .await
            .unwrap();

        let (unpacked_msg, _) = didcomm_service
            .unpack(&signed_msg, &UnpackOptions::default())
            .await
            .unwrap();

        assert_eq!(msg, unpacked_msg);
    }

    #[tokio::test]
    async fn test_didcomm_pack_plaintext() {
        let kms = LocalKms::new();
        let did_resolver = UniversalResolver::default();

        let didcomm_service = DIDCommService::new(kms, did_resolver.clone(), did_resolver);

        let msg = Message::build(
            "1234567890".to_owned(),
            "http://example.com/protocols/lets_do_lunch/1.0/proposal".to_owned(),
            json!({}),
        )
        .finalize();

        let result = didcomm_service.pack_plaintext(&msg).await.unwrap();

        let expected_result = "{\
        \"id\":\"1234567890\",\
        \"typ\":\"application/didcomm-plain+json\",\
        \"type\":\"http://example.com/protocols/lets_do_lunch/1.0/proposal\",\
        \"body\":{}\
        }";

        assert_eq!(expected_result, result);
    }

    async fn create_did_and_key_metadata_by_key_type(
        kms: &LocalKms,
        kt: KeyType,
    ) -> (DID, KeyMetadata) {
        let (kid, kh) = kms
            .create_and_handle(kt, kms::CreateOptions::default())
            .await
            .unwrap();

        // TODO: did_peer crate does not support the service format expected in didcomm crate.
        //  In did_peer service_endpoint is a URL, but in didcomm service_endpoint is expected as an object
        // let service: Service = serde_json::from_value(json! ({
        //     "id": "did:example:123456789abcdefghi#didcomm-1",
        //     "type": "DIDCommMessaging",
        //     "serviceEndpoint": [{
        //         "uri": "https://example.com/path",
        //         "accept": [
        //             "didcomm/v2",
        //             "didcomm/aip2;env=rfc587"
        //         ],
        //         "routingKeys": ["did:example:somemediator#somekey"]
        //     }]
        // }))
        // .unwrap();

        let did = DIDPeer::generate_did_peer4(
            &[VerificationMethodKey {
                key: &kh,
                verification_relationships: vec![
                    VerificationRelationshipType::Authentication,
                    VerificationRelationshipType::Assertion,
                    VerificationRelationshipType::KeyAgreement,
                ]
                .into_iter()
                .collect(),
            }],
            &[],
        )
        .unwrap();

        let did_url = UniversalResolver::default()
            .resolve_into_any_verification_method(ssi::dids::DID::new(did.as_bytes()).unwrap())
            .await
            .unwrap()
            .unwrap()
            .id;

        (
            did,
            KeyMetadata {
                kid,
                did_url: did_url.to_string(),
            },
        )
    }
}
