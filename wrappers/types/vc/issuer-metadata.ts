import { OID4VCICredentialMetadata } from "./credential-metadata";

export type KeyProofType = "jwt" | "cwt";

export interface IssuerMetadataDisplay {
  name?: string;
  locale?: string;
  logo?: CredentialMetadataDisplayLogo;
}

/**
 * @property {string} uri REQUIRED. String value that contains a URI where the Wallet can obtain the logo of the Credential from the Credential Issuer. The Wallet needs to determine the scheme, since the URI value could use the https: scheme, the data: scheme, etc.
 * @property {string} alt_text OPTIONAL. String value of the alternative text for the logo image.
 */
export interface CredentialMetadataDisplayLogo {
  uri: string;
  alt_text: string;
}


/**
 * @property {string} name REQUIRED. String value of a display name for the Credential.
 * @property {string} locale OPTIONAL. String value that identifies the language of this object represented as a language tag taken from values defined in BCP47 [RFC5646]. Multiple display objects MAY be included for separate languages. There MUST be only one object for each language identifier.
 * @property {Object} logo OPTIONAL. Object with information about the logo of the Credential. The following non-exhaustive set of parameters MAY be included:
 * @property {string} description OPTIONAL. String value of a description of the Credential.
 * @property {string} background_color OPTIONAL. String value of a background color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
 * @property {string} text_color OPTIONAL. String value of a text color of the Credential represented as numerical color values defined in CSS Color Module Level 37 [CSS-Color].
 */
export interface CredentialMetadataDisplay {
  name: string;
  locale?: string;
  logo?: CredentialMetadataDisplayLogo;
  description?: string;
  background_color?: string;
  text_color?: string;
}

/**
 * Represents a supported proof type with its signing algorithms
 *
 * @property {string[]} proof_signing_alg_values_supported REQUIRED. Array of supported
 * signing algorithms for this proof type.
 */
export interface ProofType {
  proof_signing_alg_values_supported: Array<string>;

  [key: string]: any;
}

/**
 * Defines claims about the credential subject
 *
 * @property {boolean} [mandatory] Whether the claim is required
 * @property {string} [value_type] The data type of the claim
 * @property {Array<IssuerMetadataDisplay>} [display] Display information for the claim
 */
export interface CredentialSubjectClaims {
  mandatory?: boolean;
  value_type?: string;
  display?: Array<IssuerMetadataDisplay>;

  [key: string]: unknown;
}

/**
 * Credential Response Encryption
 *
 * @property {string[]} alg_values_supported REQUIRED. Array of JWE encryption algorithms (alg values)
 * supported by the Credential Endpoint to encode the Credential Response.
 * @property {string[]} enc_values_supported REQUIRED. Array of JWE encryption algorithms (enc values)
 * supported by the Credential Endpoint to encode the Credential Response.
 * @property {boolean} encryption_required REQUIRED. Boolean specifying whether the Credential Issuer
 * requires additional encryption on top of TLS for the Credential Response.
 */
interface CredentialResponseEncryption {
  alg_values_supported: Array<string>;
  enc_values_supported: Array<string>;
  encryption_required: boolean;
}


/**
 * Credential Issuer Metadata parameters
 *
 * @property {string} credential_issuer REQUIRED. The Credential Issuer's identifier.
 * @property {string[]} [authorization_servers] Array of strings, each identifying an OAuth 2.0
 * Authorization Server the Credential Issuer relies on for authorization.
 * @property {string} credential_endpoint REQUIRED. URL of the Credential Issuer's Credential Endpoint.
 * @property {CredentialResponseEncryption} [credential_response_encryption] Object containing information
 * about whether the Credential Issuer supports encryption of the Credential Response.
 * @property {string} [deferred_credential_endpoint] URL of the Credential Issuer's Deferred Credential Endpoint.
 * @property {string} [notification_endpoint] URL of the Credential Issuer's Notification Endpoint.
 * @property {IssuerMetadataDisplay[]} [display] Array of objects containing display properties
 * of a Credential Issuer for different languages.
 * @property {Record<string, OID4VCICredentialMetadata>} credential_configurations_supported REQUIRED.
 * Object describing specifics of the Credential that the Credential Issuer supports issuance of.
 * @see {@link https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html|OpenID for Verifiable Credential Issuance}
 */
interface IssuerMetadata {
  credential_issuer: string;
  authorization_servers?: Array<string>;
  credential_endpoint: string;
  batch_credential_endpoint?: string;
  deferred_credential_endpoint?: string;
  notification_endpoint?: string;
  credential_response_encryption?: CredentialResponseEncryption,
  credential_configurations_supported: Record<string, OID4VCICredentialMetadata>;
  display?: IssuerMetadataDisplay[];
}


export type OID4VCIIssuerMetadata = IssuerMetadata;
