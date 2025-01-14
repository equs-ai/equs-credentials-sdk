declare enum Predicate {
	Required = 0,
	Preferred = 1,
}

interface ConstraintsField {
	path: Array<string>;
	id?: string;
	purpose?: string;
	name?: string;
	predicate?: Predicate;
	filter?: any;
	optional?: boolean;
	intent_to_retain?: boolean;
}

declare enum ConstraintsLimitDisclosure {
	Required = 0,
	Preferred = 1,
}

interface Constraints {
	fields?: Array<ConstraintsField>;
	limit_disclosure?: ConstraintsLimitDisclosure;
}

type ClaimFormatPayload =
	| { alg: string[] }
	| { alg_values_supported: string[] }
	| { proof_type: string[] }
	| {
			"sd-jwt_alg_values": string[];
			"kb-jwt_alg_values": string[];
	  }
	| any;

interface InputDescriptor {
	id: string;
	constraints: Constraints;
	name?: string;
	purpose?: string;
	format: Partial<ClaimFormatMap>;
	group?: Array<string>;
}

type ClaimFormatMap = Record<string, ClaimFormatPayload>;

export interface PresentationDefinition {
	id: string;
	input_descriptors: Array<InputDescriptor>;
	submission_requirements?: Array<any>;
	name?: string;
	purpose?: string;
	format?: Partial<ClaimFormatMap>;
}
