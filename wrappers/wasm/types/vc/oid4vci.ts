import {NonceData} from "../crypto";

/**
 * A deferred credential response.
 *
 * Used when the credential issuance process is asynchronous and the credential is not immediately available.
 *
 * # Fields:
 * - `transaction_id`: can be used to poll or reference the transaction status for a later retrieval.
 */
export interface CredentialDeferred {
  transaction_id: string
}

/**
 * An immediate credential response.
 *
 * Used when the credential is immediately available as part of the response.
 * It contains the issued `credential` and may include an optional `notification_id` for tracking
 * notification events related to the issuance.
 *
 * # Fields:
 * - `credential`: Verifiable Credential.
 * - `notification_id`: for tracking notification events related to the issuance.
 */
export interface CredentialImmediate {
  credential: Credential
  notification_id?: string
}

/**
 * An OID4VP credential response
 *
 * # Fields:
 * - `data`: contains `CredentialResult`.
 * - `nonce_data`: contains optional `NonceData` for subsequent calls.
 */
export interface CredentialResponse {
  data: CredentialDeferred | CredentialImmediate
  nonce_data?: NonceData
}
