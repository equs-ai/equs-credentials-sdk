interface AuthorizationCodeGrant {
	issuer_state?: string;
	authorization_server?: string;
}

interface TransactionCode {
	length?: number;
	input_mode?: string;
	description?: string;
}

interface PreAuthorizationCodeGrant {
	pre_authorized_code: string;
	tx_code?: TransactionCode;
	interval?: number;
}

export interface CredentialOfferGrants {
	authorization_code?: AuthorizationCodeGrant;
	pre_authorized_code?: PreAuthorizationCodeGrant;
}
