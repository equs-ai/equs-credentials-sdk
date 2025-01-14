import { CredentialFormats, JwkAlgorithm } from "./common";
import { CredentialMetadataDisplay, CredentialSubjectClaims, KeyProofType, ProofType } from "./issuer-metadata";

interface CredentialMetadataSdJwtVc extends CredentialMetadataCommon<"vc+sd-jwt"> {
	format: "vc+sd-jwt";
	vct: string;
	claims?: CredentialSubjectClaims;
}

interface CredentialMetadataCommon<CF extends CredentialFormats> {
	format: CF;
	scope?: string;
	cryptographic_binding_methods_supported?: Array<string>;
	credential_signing_alg_values_supported?: Array<JwkAlgorithm>;
	proof_types_supported?: Partial<Record<KeyProofType, ProofType>>;
	display?: Array<CredentialMetadataDisplay>;

	[key: string]: unknown;
}

type CredentialMetadata<CF extends CredentialFormats> = CredentialMetadataCommon<CF> & CredentialMetadataSdJwtVc;

export type OID4VCICredentialMetadata = CredentialMetadata<CredentialFormats>;
