export interface PackEncryptedOptions {
  /**
   * If `true` and message is authenticated than information about sender will be protected from mediators, but
   * additional re-encryption will be required. For anonymous messages this property will be ignored.
   * Default false.
   */
  protect_sender?: boolean;

  /**
   * Whether the encrypted messages need to be wrapped into `Forward` messages to be sent to Mediators
   * as defined by the `Forward` protocol.
   * Default true.
   */
  forward?: boolean;

  /**
   * if forward is enabled these optional headers can be passed to the wrapping `Forward` messages.
   * If forward is disabled this property will be ignored.
   */
  forward_headers?: Array<[string, string]>;

  /**
   * Identifier (DID URL) of messaging service (https://identity.foundation/didcomm-messaging/spec/#did-document-service-endpoint).
   * If DID contains multiple messaging services it allows specify what service to use.
   * If not present first service will be used.
   */
  messaging_service?: string;

  /**
   *  Algorithm used for authenticated encryption.
   * Default "A256cbcHs512Ecdh1puA256kw"
   */
  enc_alg_auth?: "A256cbcHs512Ecdh1puA256kw";

  /**
   * Algorithm used for anonymous encryption.
   * Default "Xc20pEcdhEsA256kw"
   */
  enc_alg_anon?: "A256cbcHs512EcdhEsA256kw" | "Xc20pEcdhEsA256kw" | "A256gcmEcdhEsA256kw";
}

export interface PackEncryptedMetadata {
  /**
   * Information about messaging service used for message preparation.
   * Practically `service_endpoint` field can be used to transport the message.
   */
  messaging_service?: MessagingServiceMetadata;

  /**
   * Identifier (DID URL) of sender key used for message encryption.
   */
  from_kid?: string;

  /**
   * Identifier (DID URL) of sender key used for message sign.
   */
  sign_by_kid?: string;

  /**
   * Identifiers (DID URLs) of recipient keys used for message encryption.
   */
  to_kids: Array<string>;
}

export interface MessagingServiceMetadata {
  /**
   * Identifier (DID URL) of used messaging service.
   */
  id: string;

  /**
   * Service endpoint of used messaging service.
   */
  service_endpoint: string;
}

export interface PackSignedMetadata {
  /**
   * Identifier (DID URL) of sign key.
   */
  sign_by_kid: string;
}
