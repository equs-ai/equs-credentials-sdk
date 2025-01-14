import { OID4VCICredentialMetadata } from "./credential-metadata";

type KeyProofType = "jwt" | "cwt";

interface IssuerMetadataDisplay {
	name?: string;
	locale?: string;
}

interface CredentialMetadataDisplayLogo {
	url: string;
	alt_text: string;
}

interface CredentialMetadataDisplay {
	name: string;
	locale?: string;
	logo?: CredentialMetadataDisplayLogo;
	description?: string;
	background_color?: string;
	text_color?: string;
}

interface ProofType {
	proof_signing_alg_values_supported: Array<string>;

	[key: string]: any;
}

interface CredentialSubjectClaims {
	mandatory?: boolean;
	value_type?: string;
	display?: Array<IssuerMetadataDisplay>;

	[key: string]: unknown;
}

interface IssuerMetadata {
	credential_issuer: string;
	authorization_servers?: Array<string>;
	credential_endpoint: string;
	batch_credential_endpoint?: string;
	deferred_credential_endpoint?: string;
	notification_endpoint?: string;
	credential_response_encryption_alg_values_supported?: Array<string>;
	credential_response_encryption_enc_values_supported?: Array<string>;
	require_credential_response_encryption?: boolean;
	credential_configurations_supported: Record<string, OID4VCICredentialMetadata>;
	display?: IssuerMetadataDisplay[];
}

export type OID4VCIIssuerMetadata = IssuerMetadata;
