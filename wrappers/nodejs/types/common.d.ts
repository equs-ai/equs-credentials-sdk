import { ClaimFormatPayload } from "./presentation-definition";

export const enum CredentialFormats {
	VCSDJWT = "vc+sd-jwt",
	JWTVCJSON = "jwt_vc_json",
	JWTVCJSONLD = "jwt_vc_json-ld",
	LDPVC = "ldp_vc",
	MSOMDOC = "mso_mdoc",
}

export const enum JwkAlgorithm {
	HS256 = "HS256",
	HS384 = "HS384",
	HS512 = "HS512",
	RS256 = "RS256",
	RS384 = "RS384",
	RS512 = "RS512",
	PS256 = "PS256",
	PS384 = "PS384",
	PS512 = "PS512",
	EdDSA = "EdDSA",
	EdBlake2b = "EdBlake2b",
	ES256 = "ES256",
	ES384 = "ES384",
	ES256K = "ES256K",
	ES256KR = "ES256K-R",
	ESBlake2b = "ESBlake2b",
	ESBlake2bK = "ESBlake2bK",
}

export type ClaimFormatMap = Record<string, ClaimFormatPayload>;
