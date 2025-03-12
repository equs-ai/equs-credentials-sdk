// @ts-expect-error dist will be available after build
import { DIDDocument, ResolutionOptionsParameter } from "../../dist";

export interface DIDDocMetadata {
  deactivated?: boolean;
}

export interface DIDMetadata {
  contentType?: string;
}

/**
 * The result of a DID resolution.
 *
 * @property {DIDDocument} document - The resolved DID Document.
 * @property {DIDDocMetadata} documentMetadata - Metadata related to the DID Document (e.g., deactivation status).
 * @property {DIDDocMetadata} metadata - Additional resolution metadata (e.g., content type).
 */
export interface DIDResolution {
  document: DIDDocument;
  documentMetadata: DIDDocMetadata;
  metadata: DIDMetadata;
}

export declare class ResolutionOptions {
  accept?: "application/did+json" | "application/did+ld+json";
  parameters: ResolutionOptionsParameter;
}
