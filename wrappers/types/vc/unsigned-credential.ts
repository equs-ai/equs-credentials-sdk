import { JWK } from "./credential-request";
import { Claims } from "./claims";

/**
 * Selective-disclosure strategy for SD-JWT issuance.
 *
 * Captures the decision encoded in {@link UnsignedSdJwtCredential.disclosure_strategy}:
 * `"AllLevels"` means every nested claim is independently disclosable; the
 * `{ Custom: [...] }` form lists explicit JSON-path selectors.
 *
 * Externally-tagged serialisation, matching the Rust `DisclosureStrategy` enum.
 */
export type DisclosureStrategy = "AllLevels" | { Custom: string[] };

/**
 * SD-JWT variant of an unsigned credential, ready for signing.
 *
 * Carries fully-prepared claims and the disclosure context. SD-JWT-internal fields
 * (`_sd`, `_sd_alg`, `cnf`) are added by the SD-JWT issuer during signing.
 *
 * @property {Claims} claims Fully prepared claims as a JSON object.
 * @property {DisclosureStrategy} disclosure_strategy Selective-disclosure strategy.
 * @property {JWK} holder_key Holder's public key for `cnf` key-binding.
 * @property {Record<string, string>} extra_headers Extra JWT header parameters (typ, kid).
 * @property {string} issuer_key_id Routing hint identifying which issuer key the
 *   unsigned credential expects to be signed with.
 */
export interface UnsignedSdJwtCredential {
  claims: Claims;
  disclosure_strategy: DisclosureStrategy;
  holder_key: JWK;
  extra_headers: Record<string, string>;
  issuer_key_id: string;
}

/**
 * LDP/JSON-LD variant of an unsigned credential, ready for signing.
 *
 * @property {Record<string, any>} unsigned_vc Unsigned JSON-LD credential
 *   (`AnySpecializedJsonCredential<Claims>` round-tripped through SSI's serde impls).
 * @property {string} issuer_did_url Issuer DID URL used as the verification method
 *   id in the proof options.
 * @property {string} issuer_key_id Routing hint identifying which issuer key the
 *   unsigned credential expects to be signed with.
 * @property {Array<string>} [mandatory_claims] JSON Pointer paths for mandatory
 *   disclosure (BBS+ selective disclosure).
 */
export interface UnsignedLdpCredential {
  unsigned_vc: Record<string, any>;
  issuer_did_url: string;
  issuer_key_id: string;
  mandatory_claims?: string[];
}

/**
 * Format-tagged union of unsigned credentials produced by `prepareCredential`
 * and consumed by `signCredential`.
 *
 * Externally-tagged serialisation: `{ "SdJwt": { ... } }` or `{ "Ldp": { ... } }`,
 * matching the Rust `UnsignedCredential` enum and the `Credential` wire format.
 */
export type UnsignedCredential =
  | { SdJwt: UnsignedSdJwtCredential }
  | { Ldp: UnsignedLdpCredential };
