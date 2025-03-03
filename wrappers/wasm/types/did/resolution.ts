// @ts-ignore
import {DIDDocument} from "../../dist"

export interface DIDDocMetadata {
  deactivated?: boolean
}

export interface DIDMetadata {
  contentType?: string
}

/**
 * The result of a DID resolution.
 *
 * Fields:
 * - `document`: The resolved DID Document.
 * - `documentMetadata`: Metadata related to the DID Document (e.g., deactivation status).
 * - `metadata`: Additional resolution metadata (e.g., content type).
 */
export interface DIDResolution {
  document: DIDDocument
  documentMetadata: DIDDocMetadata
  metadata: DIDMetadata
}