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
	[PRE_AUTH_CODE_KEY]: string;
	tx_code?: TransactionCode;
	interval?: number;
	authorization_server?: string;
}

export const PRE_AUTH_GRANT_KEY = "urn:ietf:params:oauth:grant-type:pre-authorized_code";
export const PRE_AUTH_CODE_KEY = "pre-authorized_code";

export interface CredentialOfferGrants {
	authorization_code?: AuthorizationCodeGrant;
	[PRE_AUTH_GRANT_KEY]?: PreAuthorizationCodeGrant;
}
