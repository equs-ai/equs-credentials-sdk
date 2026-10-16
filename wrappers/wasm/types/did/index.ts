export * from "./resolution";
export * from "./resolver";

/**
 * The types of verification relationships that a key may support
 */
export enum VerificationRelationshipType {
  Authentication = "Authentication",
  Assertion = "Assertion",
  KeyAgreement = "KeyAgreement",
  CapabilityInvocation = "CapabilityInvocation",
  CapabilityDelegation = "CapabilityDelegation",
}
