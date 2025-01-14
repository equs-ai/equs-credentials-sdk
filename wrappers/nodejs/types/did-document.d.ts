interface VerificationMethod {
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
	context: string | string[];
	id: string;
	alsoKnownAs?: string[];
	controller?: string | string[];
	verificationMethod?: VerificationMethod[];
	authentication?: (string | VerificationMethod)[];
	assertionMethod?: (string | VerificationMethod)[];
	keyAgreement?: (string | VerificationMethod)[];
	capabilityInvocation?: (string | VerificationMethod)[];
	capabilityDelegation?: (string | VerificationMethod)[];
	public_key?: Array<VerificationMethod>;
	service?: Service[];
	proof?: IProof | IProof[];
	property_set?: Record<string, any>;
}
