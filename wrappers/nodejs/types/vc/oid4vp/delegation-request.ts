/**
 * Fields shared by every `DelegationRequest` variant.
 *
 * @property credentialIds - The credential id(s) in the presentation query this delegation
 *   targets (becomes `credential_ids` on the transaction-data item).
 * @property payloadClaims - Claims to carry in the delegate payload. Must not contain `cnf` or `_sd`.
 */
export type DelegationRequestBase = {
  credentialIds: Array<string>;
  payloadClaims?: Record<string, any> | null;
};

/**
 * A terminal grant: the Delegate Holder receives a dSD-JWT with no further holder
 * binding.
 */
export type OpenDelegationRequest = DelegationRequestBase & {
  format: "dSD-JWT";
};

/**
 * The Delegate Holder will add its own KB-JWT, bound to `delegateJwk`.
 *
 * @property delegateJwk - The Delegate Holder's confirmation JWK. Carried inside the delegate payload as `cnf: { jwk }`.
 */
export type HolderBindingDelegationRequest = DelegationRequestBase & {
  format: "dSD-JWT+KB";
  delegateJwk: Record<string, any>;
};

/**
 * Inputs for asking a Holder to delegate a credential to *this* party (the Delegate Holder).
 */
export type DelegationRequest = OpenDelegationRequest | HolderBindingDelegationRequest;

export const DelegationRequest = {
  open(credentialIds: Array<string>, payloadClaims?: Record<string, any> | null): OpenDelegationRequest {
    return { format: "dSD-JWT", credentialIds, payloadClaims };
  },

  holderBinding(
    credentialIds: Array<string>,
    delegateJwk: Record<string, any>,
    payloadClaims?: Record<string, any> | null,
  ): HolderBindingDelegationRequest {
    return { format: "dSD-JWT+KB", credentialIds, delegateJwk: delegateJwk, payloadClaims };
  },
};
