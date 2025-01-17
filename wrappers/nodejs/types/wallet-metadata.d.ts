import { ClaimFormatMap } from "./common";

export interface WalletMetadata {
	authorization_endpoint: string;
	vp_formats_supported: ClaimFormatMap;
	response_types_supported?: Array<string>;
	client_id_schemes_supported?: Array<string>;
	request_object_signing_alg_values_supported?: Array<string>;
	scopes_supported?: Array<string>;
	subject_syntax_types_supported?: Array<string>;
	id_token_types_supported?: Array<string>;
	id_token_signing_alg_values_supported?: Array<string>;

	[key: string]: unknown;
}
