export interface DIDVerificationMethod {
  /**
   * Verification method identifier.
   */
  id: string;
  /**
   * type {@link https://www.w3.org/TR/did-core/#dfn-did-urls|property} of a verification method map.
   * Should be registered in {@link https://www.w3.org/TR/did-spec-registries/#verification-method-types|DID Specification
   * registries - Verification method types}.
   */
  type: string;
  /**
   * {@link https://w3c-ccg.github.io/ld-proofs/#controller|controller} property of a verification
   * method map.
   *
   * Not to be confused with the {@link https://www.w3.org/TR/did-core/#dfn-controller|controller} property of a DID document.
   */
  controller: string;

  /**
   * Verification methods properties.
   */
  [key: string]: unknown;
}

/**
 * DID Service.
 *
 * Services express ways of communicating with the DID subject or associated
 * entities.
 */
export interface Service {
  /**
   * id property (URI) of a service map.
   */
  id: string;
  type: string;
  serviceEndpoint: string | string[] | Record<string, any>;
}

export interface IProof {
  type: string;

  [key: string]: unknown;
}

export interface DIDDocument {
  /**
   * The JSON-LD Context is either a string or a list containing any combination of strings and/or ordered maps.
   */
  context?: string | string[];
  /**
   * DID subject identifier.
   *
   * See: https://www.w3.org/TR/did-core/#did-subject
   */
  id: string;
  /**
   * Other URIs for the DID subject.
   *
   * See: https://www.w3.org/TR/did-core/#also-known-as
   */
  alsoKnownAs?: string[];
  /**
   * Controllers(s).
   *
   * See: https://www.w3.org/TR/did-core/#did-controller
   */
  controller?: string | string[];
  /**
   * `verificationMethod` property of a DID document, expressing verification methods.
   *
   * See: https://www.w3.org/TR/did-core/#dfn-verificationmethod
   */
  verificationMethod?: DIDVerificationMethod[];
  /**
   * Verification relationships.
   *
   * Properties that express the relationship between the DID subject and a
   * verification method using a verification relationship.
   * authentication, assertionMethod, keyAgreement, capabilityInvocation, capabilityDelegation
   * See: https://www.w3.org/TR/did-core/#verification-relationships
   */
  authentication?: (string | DIDVerificationMethod)[];
  assertionMethod?: (string | DIDVerificationMethod)[];
  keyAgreement?: (string | DIDVerificationMethod)[];
  capabilityInvocation?: (string | DIDVerificationMethod)[];
  capabilityDelegation?: (string | DIDVerificationMethod)[];
  /**
   * `service` property of a DID document, expressing services, generally as endpoints.
   *
   * See: https://www.w3.org/TR/did-core/#services
   */
  service?: Service[];
  /**
   * `publicKey` property of a DID document (deprecated in favor of `verificationMethod`).
   *
   * See: https://www.w3.org/TR/did-spec-registries/#publickey
   */
  publicKey?: Array<DIDVerificationMethod>;
  proof?: IProof | IProof[];

  /**
   * Additional properties of a DID document. Some may be registered in DID Specification Registries.
   *
   * See: https://www.w3.org/TR/did-spec-registries/#did-document-properties
   */
  [key: string]: unknown;
}
