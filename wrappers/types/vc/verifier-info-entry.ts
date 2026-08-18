/**
 * A single `verifier_info` entry for an OID4VP authorization request.
 *
 * Carries an attestation about the Verifier relevant to the Credential Request.
 *
 * @property format - Identifier of the attestation format.
 * @property data - The attestation itself. A compact JWS is passed as a string, any other format
 *   as a JSON object.
 * @property credential_ids - Binds the attestation to specific DCQL credential queries. Omit to
 *   apply it to the whole request.
 */
export type VerifierInfoEntry = {
  format: string;
  data: string | Record<string, any>;
  credential_ids?: Array<string> | null;
};
