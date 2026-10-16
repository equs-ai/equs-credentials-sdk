/**
 * Fields common to every transaction-data item, whatever its `type`.
 *
 * @property credential_ids - List of credential IDs this transaction data applies to
 * @property transaction_data_hashes_alg - Hash algorithms used for transaction data
 *   (null for some types, including `delegate`)
 */
export type TransactionDataItemBase = {
  credential_ids: Array<string>;
  transaction_data_hashes_alg?: Array<string> | null;
};

/**
 * A `delegate` transaction-data item (dSD-JWT delegation).
 *
 * @property type - Discriminator; always `"delegate"`.
 * @property format - `"dSD-JWT"` for a terminal grant, `"dSD-JWT+KB"` when the Delegate
 *   Holder adds its own KB-JWT (the delegate payload then carries a `cnf`).
 * @property delegate_payload_disclosure - base64url(`[salt, { cnf?, ...claims }]`).
 * @property delegate_disclosures - Additional disclosure.
 */
export type DelegateTransactionDataItem = TransactionDataItemBase & {
  type: "delegate";
  format: "dSD-JWT" | "dSD-JWT+KB";
  delegate_payload_disclosure: string;
  delegate_disclosures?: Array<string> | null;
};

/**
 * A transaction-data item of any other `type`.
 */
export type UnknownTransactionDataItem = TransactionDataItemBase & {
  type: string;
  [key: string]: unknown;
};

/**
 * Transaction data item for OID4VP authorization requests.
 */
export type TransactionDataItem =
  | DelegateTransactionDataItem
  | UnknownTransactionDataItem;
