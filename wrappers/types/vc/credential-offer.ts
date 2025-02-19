import { CredentialOfferGrants } from "./credential-offer-grants";

export interface OID4VCICredentialOffer {
  credential_issuer: string;
  credential_configuration_ids: Array<string>;
  grants?: CredentialOfferGrants;
}
