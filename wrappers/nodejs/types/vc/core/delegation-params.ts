/**
 * How a KB-SD-JWT link binds to the preceding component in a dSD-JWT chain.
 *
 * - `SdHash` - `sd_hash` over the preceding JWT and its forwarded disclosures (crate default).
 *   The Delegate Holder MUST keep the preceding component's disclosures on the wire.
 * - `IssuerJwtHash` - `issuer_jwt_hash` over the preceding JWT only. Lets a Delegate Holder
 *   drop the preceding component's disclosures.
 */
export type ChainBindingMode = "SdHash" | "IssuerJwtHash";

/**
 * Delegation hop parameters for {@link VcCoreHolder.createDelegatedCredential}.
 *
 * @property delegatePayloads - The delegate payload alternatives for this hop (one entry = single alternative).
 * @property claimsToDisclose - Claims from the original credential to forward (omitted = forward none / use default).
 * @property dropDisclosures - Disclosure strings to drop from the wire (omitted = keep all).
 * @property binding - Chain binding mode. Defaults to `SdHash` when omitted.
 * @property aud - Audience to bind the grant to (the requesting Delegate Holder). When set, it is
 *   written into each delegate payload as the `aud` claim.
 * @property nonce - Request nonce to bind the grant to. When set, written into each delegate payload
 *   as the `nonce` claim.
 */
export type DelegationParams = {
  delegatePayloads: Array<Record<string, any>>;
  claimsToDisclose?: Record<string, any> | null;
  dropDisclosures?: Array<string> | null;
  binding?: ChainBindingMode | null;
  aud?: string | null;
  nonce?: string | null;
};
