import {CredentialOfferGrants} from "./credential-offer-grants";

/**
 * JSON-encoded Credential Offer object parameters
 *
 * @property {string} credential_issuer REQUIRED. The URL of the Credential Issuer from which
 * the Wallet is requested to obtain one or more Credentials.
 * @property {string[]} credential_configuration_ids REQUIRED. Array of unique strings that
 * each identify one of the keys in the name/value pairs stored in the
 * `credential_configurations_supported` Credential Issuer metadata.
 * @property {CredentialOfferGrants} [grants] Object indicating to the Wallet the Grant Types
 * the Credential Issuer's Authorization Server is prepared to process for this Credential Offer.
 *
 * Additional Credential Offer parameters, that are not covered by OID4VCI specification, can be retrieved by their key.
 *
 * @see {@link https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html#name-credential-offer-parameters|OpenID for Verifiable Credential Issuance}
 */
export interface OID4VCICredentialOffer {
  credential_issuer: string;
  credential_configuration_ids: Array<string>;
  grants?: CredentialOfferGrants;

  [additional_field: string]: any;
}