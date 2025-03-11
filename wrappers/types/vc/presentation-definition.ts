import { ClaimFormatMap } from "./common";

export declare enum Predicate {
  Required = 0,
  Preferred = 1,
}

/**
 * ConstraintsField objects are used to describe the constraints that a
 * {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder|Holder}
 * must satisfy to fulfill an Input Descriptor.
 *
 * @see {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object|Input Descriptor Object Specification}
 */
export interface ConstraintsField {
  path: Array<string>;
  id?: string;
  purpose?: string;
  name?: string;
  predicate?: Predicate;
  filter?: any;
  optional?: boolean;
  intent_to_retain?: boolean;
}

/**
 * Controls disclosure limitations for credential data
 *
 * @enum {number}
 * @property {number} Required Selective disclosure must be used
 * @property {number} Preferred Selective disclosure is preferred but not mandatory
 */
export declare enum ConstraintsLimitDisclosure {
  Required = 0,
  Preferred = 1,
}

/**
 * Constraints are objects used to describe the constraints that a
 * {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder|Holder} must satisfy to fulfill an Input Descriptor.
 *
 * A constraint object MAY be empty, or it may include a `fields` and/or `limit_disclosure` property.
 *
 * @see {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object|Input Descriptor Object Specification}
 */
export interface Constraints {
  fields?: Array<ConstraintsField>;
  limit_disclosure?: ConstraintsLimitDisclosure;
}

/**
 * Claim format payload
 */
export type ClaimFormatPayload =
  | { alg: string[] }
  | { alg_values_supported: string[] }
  | { proof_type: string[] }
  | {
  "sd-jwt_alg_values": string[];
  "kb-jwt_alg_values": string[];
}
  | any;

/**
 * Input Descriptors are objects used to describe the information a
 * {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier|Verifier} requires of a
 * {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder|Holder}.
 *
 * All Input Descriptors MUST be satisfied, unless otherwise specified by a
 * {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:feature|Feature}.
 *
 * @see {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#input-descriptor-object|Input Descriptor Object Specification}
 */
export interface InputDescriptor {
  id: string;
  constraints: Constraints;
  name?: string;
  purpose?: string;
  format: Partial<ClaimFormatMap>;
  group?: Array<string>;
}


/**
 * A presentation definition is a JSON object that describes the information a {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier|Verifier} requires of a {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder|Holder}.
 *
 * > Presentation Definitions are objects that articulate what proofs a {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier|Verifier} requires.
 * > These help the {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier|Verifier} to decide how or whether to interact with a {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder|Holder}.
 *
 * Presentation Definitions are composed of inputs, which describe the forms and details of the
 * proofs they require, and optional sets of selection rules, to allow
 * {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder|Holder}s flexibility
 * in cases where different types of proofs may satisfy an input requirement.
 *
 * @see {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-definition|Presentation Definition Specification}
 */
export interface PresentationDefinition {
  id: string;
  input_descriptors: Array<InputDescriptor>;
  submission_requirements?: Array<any>;
  name?: string;
  purpose?: string;
  format?: Partial<ClaimFormatMap>;
}
