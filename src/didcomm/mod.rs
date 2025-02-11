//! DIDComm V2 Messaging

use common_macros::DebugError;
use snafu::{Location, ResultExt, Snafu};
use std::marker::PhantomData;
use tracing::{instrument, Level};

use crate::did::universal::UniversalResolver;
use crate::didcomm::did_resolver::DidResolverWrapper;
use crate::didcomm::kms::KmsWrapper;
use crate::kms::{DerivativeKms, ECDH1PUParams, ECDHESParams, KeyHandle, Kms};

mod did_resolver;
mod kms;

/// Algorithms for authenticated encryption.
pub type AuthCryptAlg = didcomm::algorithms::AuthCryptAlg;
/// DIDComm message attachment.
pub type Attachment = didcomm::Attachment;
/// Builder for a DIDComm message attachment.
pub type AttachmentBuilder = didcomm::AttachmentBuilder;
/// DIDComm message
pub type Message = didcomm::Message;
/// Builder for a DIDComm message.
pub type MessageBuilder = didcomm::MessageBuilder;
/// Allow fine configuration of packing process
pub type PackEncryptedOptions = didcomm::PackEncryptedOptions;
/// Additional metadata about this encrypt method execution like used keys identifiers, used messaging service.
pub type PackEncryptedMetadata = didcomm::PackEncryptedMetadata;
/// Additional metadata about this pack method execution like used key identifiers.
pub type PackSignedMetadata = didcomm::PackSignedMetadata;
/// Allows fine customization of unpacking process
pub type UnpackOptions = didcomm::UnpackOptions;
/// Additional metadata about this unpack method execution like trust predicates and used keys identifiers.
pub type UnpackMetadata = didcomm::UnpackMetadata;

/// Error expected during `DIDComm Messaging` operations.
#[derive(Snafu, DebugError)]
#[snafu(visibility(pub))]
#[snafu(display("DIDComm error"))]
pub struct Error {
    source: didcomm::error::Error,
    #[snafu(implicit)]
    location: Location,
}

/// `Result` alias for `DIDComm`-specific [Error].
pub type Result<T> = std::result::Result<T, Error>;

/// A DIDComm service that provides packing and unpacking of DIDComm messages.
pub struct DIDCommService<KMS, KH>
where
    KMS: Kms<KH>
        + DerivativeKms<ECDH1PUParams, Output = Vec<u8>>
        + DerivativeKms<ECDHESParams, Output = Vec<u8>>,
    KH: KeyHandle,
{
    kms: KmsWrapper<KMS, KH>,
    did_resolver: DidResolverWrapper,
    _phantom: PhantomData<KH>,
}

impl<KMS, KH> DIDCommService<KMS, KH>
where
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
    pub fn new(kms: KMS, did_resolver: UniversalResolver) -> Self {
        DIDCommService {
            kms: KmsWrapper::new(kms, did_resolver.clone()),
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
    use crate::did::didpeer::{
        DIDPeer, DidPeerService, VerificationMethodKey, VerificationRelationshipType,
    };
    use crate::did::universal::UniversalResolver;
    use crate::did::{DIDResolver, DID};
    use crate::didcomm::{DIDCommService, Message, UnpackOptions};
    use crate::inmem::kms::LocalKms;
    use crate::kms;
    use crate::kms::{KeyType, Kms};
    use crate::vc::core::KeyMetadata;
    use serde_json::json;

    #[tokio::test]
    async fn pack_encrypted_succeeded() {
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
        let didcomm_service = DIDCommService::new(kms, did_resolver);

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
        assert_eq!(
            metadata.messaging_service.unwrap().service_endpoint,
            "https://example.com/path"
        );

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

    #[should_panic(expected = "No sender secrets found")]
    #[tokio::test]
    async fn pack_encrypted_failed_with_incorrect_sender_did() {
        let kms = LocalKms::new();

        let sender_did = "did:peer:4zQmdrR8n3sYAuDh7n3Ztwhc22dFTLwXcq6M75AXPuvdCMWw:z3c91SEw\
        qVio1Xpv8jBeTSQK3C9ahjbRvKxyLd6H8EnhfG5cCg9cqyxxUpLdeeMzs5raX3YyJbrNqoNqVPoZ6iHtAKGx24VDxbm\
        BTKWkm4YYcSXAJEKxWfrteVzXLATrfBqZz4t8UcTpL4g61JRcxfSepifdJARJdJe4idgfTcVKR3YQ1hYQchNX443PnP\
        XsG1NJ9U5Jb6AHQK78Y7ydDUqj15RUxQdqCsURhFqoCASnB9DN9JCP6zpqCzy2cW2AVcXNLGrd3HLoCBDUScXhqrwy4\
        8hcYHW86eRwQmYvgJPCrMLkLe5KRABQic2XEvHsv5HsCQFFpfTD6iSyqqSB2W3YvkvLb5giFwJsCz1PpXbKZt9gDkgP\
        H54RmqFG1Y8Y4Mx2A9umWhJuUdS"
            .to_string();

        let (recipient_did, recipient_key_metadata) =
            create_did_and_key_metadata_by_key_type(&kms, KeyType::P256).await;

        let didcomm_service = DIDCommService::new(kms, UniversalResolver::default());

        let encryption_options = didcomm::PackEncryptedOptions {
            protect_sender: true,
            ..Default::default()
        };

        let msg = Message::build(
            sender_did.to_owned(),
            recipient_did.to_owned(),
            json!("example-body"),
        )
        .to(recipient_did.to_owned())
        .from(sender_did.to_owned())
        .finalize();

        didcomm_service
            .pack_encrypted(
                &msg,
                &recipient_did,
                Some(&sender_did),
                None,
                &encryption_options,
            )
            .await
            .unwrap();
    }

    #[should_panic(expected = "No recipient secrets found")]
    #[tokio::test]
    async fn unpack_failed_with_incorrect_recipient_did() {
        let kms = LocalKms::new();

        let (sender_did, sender_key_metadata) =
            create_did_and_key_metadata_by_key_type(&kms, KeyType::P256).await;
        let recipient_did = "did:peer:4zQmdrR8n3sYAuDh7n3Ztwhc22dFTLwXcq6M75AXPuvdCMWw:z3c91SEw\
        qVio1Xpv8jBeTSQK3C9ahjbRvKxyLd6H8EnhfG5cCg9cqyxxUpLdeeMzs5raX3YyJbrNqoNqVPoZ6iHtAKGx24VDxbm\
        BTKWkm4YYcSXAJEKxWfrteVzXLATrfBqZz4t8UcTpL4g61JRcxfSepifdJARJdJe4idgfTcVKR3YQ1hYQchNX443PnP\
        XsG1NJ9U5Jb6AHQK78Y7ydDUqj15RUxQdqCsURhFqoCASnB9DN9JCP6zpqCzy2cW2AVcXNLGrd3HLoCBDUScXhqrwy4\
        8hcYHW86eRwQmYvgJPCrMLkLe5KRABQic2XEvHsv5HsCQFFpfTD6iSyqqSB2W3YvkvLb5giFwJsCz1PpXbKZt9gDkgP\
        H54RmqFG1Y8Y4Mx2A9umWhJuUdS"
            .to_string();

        let didcomm_service = DIDCommService::new(kms, UniversalResolver::default());

        let encryption_options = didcomm::PackEncryptedOptions {
            protect_sender: true,
            ..Default::default()
        };

        let msg = Message::build(
            sender_did.to_owned(),
            recipient_did.to_owned(),
            json!("example-body"),
        )
        .to(recipient_did.to_owned())
        .from(sender_did.to_owned())
        .finalize();

        let (packed_msg, _) = didcomm_service
            .pack_encrypted(
                &msg,
                &recipient_did,
                Some(&sender_did),
                None,
                &encryption_options,
            )
            .await
            .unwrap();

        didcomm_service
            .unpack(&packed_msg, &UnpackOptions::default())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn pack_signed_succeeded() {
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

        let didcomm_service = DIDCommService::new(kms.clone(), did_resolver);

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
    async fn pack_plaintext_succeeded() {
        let kms = LocalKms::new();
        let did_resolver = UniversalResolver::default();

        let didcomm_service = DIDCommService::new(kms, did_resolver);

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

        let service: DidPeerService = serde_json::from_value(json! ({
            "id": "#didcomm-1",
            "type": "DIDCommMessaging",
            "serviceEndpoint": {
                "uri": "https://example.com/path",
                "accept": [
                    "didcomm/v2",
                    "didcomm/aip2;env=rfc587"
                ],
                "routingKeys": ["#key-0"]
            }
        }))
        .unwrap();

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
            &[service],
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
