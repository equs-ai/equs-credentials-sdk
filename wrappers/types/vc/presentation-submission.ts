import { CredentialFormats } from "./common";

/**
 * Descriptor Maps are objects used to describe the information a
 * {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:holder|Holder} provides to a
 * {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier|Verifier}.
 *
 * @see {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission|Presentation Submission Specification}
 */
export interface DescriptorMap {
  id: string;
  format: CredentialFormats;
  path: string;
  path_nested?: DescriptorMap;
}

/**
 * Presentation Submissions are objects embedded within target
 * {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:claim|Claim} negotiation
 * formats that express how the inputs presented as proofs to a
 * {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#term:verifier|Verifier} are
 * provided in accordance with the requirements specified in a PresentationDefinition.
 *
 * Embedded Presentation Submission objects MUST be located within target data format as
 * the value of a `presentation_submission` property.
 *
 * @see {@link https://identity.foundation/presentation-exchange/spec/v2.0.0/#presentation-submission|Presentation Submission Specification}
 */
export interface PresentationSubmission {
  id: string;
  definition_id: string;
  descriptor_map: Array<DescriptorMap>;
}
