import {
  _UniversalDIDResolver,
  _VCCoreCredentialSigner,
  Credential,
  Kms,
  UniversalDIDResolver,
  UnsignedCredential,
} from "../../..";
import { contextEnsuredKms } from "../../utils";

/**
 * An async low-level `SignCredential` API.
 *
 * Carries only what the signing step needs — a {@link Kms} for key access and a
 * DID resolver for LDP proof assembly. Use when the prepare/sign split is
 * driven from application code (e.g. a remote signing service or HSM-backed
 * adapter) and a full {@link VCCoreIssuer} is not desired.
 *
 * This class is a hand-written wrapper over the raw napi `_VCCoreCredentialSigner`:
 * - it threads the {@link Kms} through {@link contextEnsuredKms} so the napi
 *   `ThreadsafeFunction` machinery preserves `this` on callbacks;
 * - it accepts the friendly {@link UniversalDIDResolver} (also a TS wrapper) and
 *   unwraps its inner napi resolver.
 *
 * The resulting API matches the wasm-side `VCCoreCredentialSigner`, so the same
 * application code runs against either binding.
 */
export class VCCoreCredentialSigner {
  private readonly inner: _VCCoreCredentialSigner;

  constructor(kms: Kms, didResolver: UniversalDIDResolver) {
    this.inner = new _VCCoreCredentialSigner(contextEnsuredKms(kms), didResolver.inner);
  }

  /**
   * Sign an unsigned credential and return the finished {@link Credential}.
   *
   * The `unsigned` argument is the externally-tagged JSON serialisation of the
   * SDK's {@link UnsignedCredential} enum — `{ "SdJwt": { ... } }` or
   * `{ "Ldp": { ... } }`.
   */
  async signCredential(unsigned: UnsignedCredential): Promise<Credential> {
    return await this.inner.signCredential(unsigned);
  }
}
