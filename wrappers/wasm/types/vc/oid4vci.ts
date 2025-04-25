import { Credential } from "./credential";

/**
 * A deferred credential response.
 *
 * Used when the credential issuance process is asynchronous and the credential is not immediately available.
 *
 * @property {string} transaction_id - Can be used to poll or reference the transaction status for a later retrieval.
 */
export interface CredentialDeferred {
  transaction_id: string;
}

/**
 * An immediate credential response.
 *
 * Used when the credential is immediately available as part of the response.
 * It contains the issued `credential` and may include an optional `notification_id` for tracking
 * notification events related to the issuance.
 *
 * @property {Array<Credential>} credentials - Verifiable Credentials.
 * @property {string} notification_id - For tracking notification events related to the issuance.
 */
export interface CredentialImmediate {
  credentials: Array<Credential>;
  notification_id?: string;
}

/**
 * An OID4VP credential response
 *
 * @property {CredentialDeferred|CredentialImmediate} data - The credential response data,
 * which may be either a {@link CredentialDeferred} or a {@link CredentialImmediate}.
 */
export interface CredentialResponse {
  data: CredentialDeferred | CredentialImmediate;
}
