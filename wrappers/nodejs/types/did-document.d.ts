export interface DIDVerificationMethod {
	id: string;
	type: string;
	controller: string;

	[key: string]: unknown;
}

interface Service {
	id: string;
	type: string;
	serviceEndpoint: string | string[] | Record<string, any>;
}

interface IProof {
	type: string;

	[key: string]: unknown;
}

export interface DIDDocument {
	context?: string | string[];
	id: string;
	alsoKnownAs?: string[];
	controller?: string | string[];
	verificationMethod?: DIDVerificationMethod[];
	authentication?: (string | DIDVerificationMethod)[];
	assertionMethod?: (string | DIDVerificationMethod)[];
	keyAgreement?: (string | DIDVerificationMethod)[];
	capabilityInvocation?: (string | DIDVerificationMethod)[];
	capabilityDelegation?: (string | DIDVerificationMethod)[];
	publicKey?: Array<DIDVerificationMethod>;
	service?: Service[];
	proof?: IProof | IProof[];

	[key: string]: unknown;
}

interface DocMetadata {
	deactivated?: boolean;
}

interface Metadata {
	contentType?: string;
}

export interface DIDResolution {
	document: DIDDocument;
	metadata: Metadata;
	document_metadata: DocMetadata;
}
