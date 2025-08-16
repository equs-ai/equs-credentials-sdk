import { CredentialFormats, JwkAlgorithm } from "./common";
import { CredentialMetadataDisplay, CredentialSubjectClaim, KeyProofType, ProofType } from "./issuer-metadata";

interface CredentialMetadataSdJwtVc extends CredentialMetadataCommon {
  format: CredentialFormats.VCSDJWT;
  vct: string;
}


interface CredentialMetadataCommon {
  format: CredentialFormats;
  scope?: string;
  cryptographic_binding_methods_supported?: Array<string>;
  credential_signing_alg_values_supported?: Array<JwkAlgorithm>;
  proof_types_supported?: Partial<Record<KeyProofType, ProofType>>;
  display?: Array<CredentialMetadataDisplay>;
  claims?: Array<CredentialSubjectClaim>;

  [key: string]: unknown;
}


/**
 * Contains metadata about a specific Credential.
 *
 * @property {CredentialFormats} format REQUIRED. String identifying the format of this Credential
 * (e.g., jwt_vc_json or ldp_vc).
 * @property {string} [scope] String identifying the scope value that this Credential Issuer
 * supports for this particular Credential.
 * @property {string[]} [cryptographic_binding_methods_supported] Array of case sensitive strings
 * identifying the representation of cryptographic key material that the issued Credential is bound to.
 * @property {string[]} [credential_signing_alg_values_supported] Array of strings identifying the
 * algorithms that the Issuer uses to sign the issued Credential.
 * @property {Partial<Record<KeyProofType, ProofType>>} [proof_types_supported] Object describing
 * specifics of the key proof(s) that the Credential Issuer supports.
 * @property {CredentialMetadataDisplay[]} [display] Array of objects containing display properties
 * of the supported Credential for different languages.

 * @see {@link https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html|OpenID for Verifiable Credential Issuance}
 */
export type OID4VCICredentialMetadata = CredentialMetadataCommon & CredentialMetadataSdJwtVc;
