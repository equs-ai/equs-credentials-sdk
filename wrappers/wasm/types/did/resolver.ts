import { ResolutionOptions, DIDResolution } from "./resolution";

/**
 * `DIDResolver`
 *
 * @property methodName - {@link DIDResolver.methodName}
 * @method resolveRepresentation - {@link DIDResolver.resolveRepresentation}
 */
export interface DIDResolver {
  /**
   * The name of the DID method supported by this resolver.
   */
  methodName: string;

  /**
   * Resolves a DID Document.
   *
   * @param {`did:${string}:${string}`} did - The DID in the format `did:method:identifier`.
   * @param {ResolutionOptions} options - Additional resolution options.
   *
   * @returns {Promise<DIDResolution>} - The {@link DIDResolution}, including the DID document and metadata.
   */
  resolveRepresentation(did: `did:${string}:${string}`, options: ResolutionOptions): Promise<DIDResolution>;
}
