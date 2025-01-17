import { CredentialOfferGrants } from "./credential-offer-grants";

interface CredentialOfferParameters {
	credential_issuer: string;
	credential_configuration_ids: Array<string>;
	grants?: CredentialOfferGrants;
}

export type OID4VCICredentialOffer = CredentialOfferParameters | { credential_offer_uri: string };
