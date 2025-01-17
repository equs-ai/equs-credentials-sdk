import { CredentialFormats, JwkAlgorithm } from "./common";
import { CredentialMetadataDisplay, CredentialSubjectClaims, KeyProofType, ProofType } from "./issuer-metadata";

interface CredentialMetadataSdJwtVc extends CredentialMetadataCommon {
	format: CredentialFormats.VCSDJWT;
	vct: string;
	claims?: CredentialSubjectClaims;
}

interface CredentialMetadataCommon {
	format: CredentialFormats;
	scope?: string;
	cryptographic_binding_methods_supported?: Array<string>;
	credential_signing_alg_values_supported?: Array<JwkAlgorithm>;
	proof_types_supported?: Partial<Record<KeyProofType, ProofType>>;
	display?: Array<CredentialMetadataDisplay>;

	[key: string]: unknown;
}

export type OID4VCICredentialMetadata = CredentialMetadataCommon & CredentialMetadataSdJwtVc;
