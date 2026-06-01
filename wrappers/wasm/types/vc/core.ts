import { KeyMetadata } from "../crypto";
import { VCFormat } from "./credential";
import { Kms } from "../kms";

// ===== Enums =====

export enum CredentialDefinitionFormat {
  SdJwt = "sdJwt",
  Ldp = "ldp",
}

export enum CredentialOfferContentFormat {
  CredDef = "credDef",
  SupportedProofs = "supportedProofs",
}

export enum CredentialStatusInfoFormat {
  TokenStatusList = "tokenStatusList",
  BitstringStatusList = "bitstringStatusList",
}

export enum VCStatusesDataFormat {
  StatusListToken = "statusListToken",
  BitstringStatusList = "bitstringStatusList",
}

export enum StatusListFormatFmt {
  StatusListTokenJwt = "statusListTokenJwt",
  StatusListTokenCwt = "statusListTokenCwt",
}

export enum StatusListFmt {
  StatusListTokenJwt = "statusListTokenJwt",
}

export enum PresentationFormat {
  JwtVp = "jwtVp",
  LdpVp = "ldpVp",
  SdJwtVp = "sdJwtVp",
}

export enum PresentationRestrictionValueType {
  String = "string",
  Pattern = "pattern",
  Array = "array",
}

// ===== Interfaces =====

export interface Proof {
  format: string;
  proof: string;
}

export interface CredentialRequestData {
  proofTolerance?: number;
}

export interface CredentialRequest {
  credDefId: string;
  credOfferId?: string;
  proof: Proof;
  protocolData?: CredentialRequestData;
}

export interface CredentialDefinitionData {
  format: CredentialDefinitionFormat;
  payload: Record<string, any>;
}

/**
 * An interface that defines how to display the claim.
 *
 * *NOTE*: will be extended in the next releases.
 */
export interface Display {}

export interface CredentialDefinition {
  credDefId: string;
  format: VCFormat;
  claims: Record<string, any>;
  supportedProofs?: Record<string, any>;
  supportedSigningAlgs?: string[];
  display?: Display;
  protocolData?: CredentialDefinitionData;
  keyMetadata: KeyMetadata;
}

export interface CredentialOfferContent {
  format: "credDef" | "supportedProofs";
  payload: Record<string, any>;
}

export interface CredentialOffer {
  credOfferId?: string;
  issuerId: string;
  credDefId: string;
  content: CredentialOfferContent;
  protocolData?: CredentialOfferData;
}

export interface CredentialStatusInfo {
  format: CredentialStatusInfoFormat;
  payload: Record<string, any>;
}

export interface VCStatusesData {
  format: VCStatusesDataFormat;
  payload: Record<string, any>;
}

export interface StatusListFormat {
  format: StatusListFormatFmt;
  payload: Record<string, any>;
}

export interface StatusList {
  format: StatusListFmt;
  payload: Record<string, any>;
}

export interface StatusListDefinition {
  id: string;
  format: StatusListFormat;
  keyMetadata: KeyMetadata;
}

export interface StatusIssuerMetadata {
  issuerId: string;
  supportedStatusLists: StatusListDefinition[];
}

/**
 * A protocol-specific data for the `Issuer`.
 *
 * *NOTE*: will be extended in the next releases.
 */
export interface IssuerMetadataData {}

export interface IssuerMetadata {
  issuerId: string;
  credDefs: CredentialDefinition[];
  protocolData?: IssuerMetadataData;
}

export enum InnerProofOfPossessionNotBeforeStrategy {
  AsIssuedAt = "asIssuedAt",
  Fixed = "fixed",
  Delay = "delay",
  Leeway = "leeway",
}

export interface InnerProofOfPossessionNotBefore {
  strategy: InnerProofOfPossessionNotBeforeStrategy;
  /** Unix timestamp in seconds. */
  fixed?: number;
  /** Seconds. */
  delay?: number;
  /** Seconds. */
  leeway?: number;
}

export class ProofOfPossessionNotBefore {
  static asIssuedAt(): InnerProofOfPossessionNotBefore {
    return { strategy: InnerProofOfPossessionNotBeforeStrategy.AsIssuedAt };
  }

  static fixed(date: Date): InnerProofOfPossessionNotBefore {
    return { strategy: InnerProofOfPossessionNotBeforeStrategy.Fixed, fixed: Math.floor(date.getTime() / 1000) };
  }

  static delay(delay_secs: number): InnerProofOfPossessionNotBefore {
    return { strategy: InnerProofOfPossessionNotBeforeStrategy.Delay, delay: delay_secs };
  }

  static leeway(leeway_secs: number): InnerProofOfPossessionNotBefore {
    return { strategy: InnerProofOfPossessionNotBeforeStrategy.Leeway, leeway: leeway_secs };
  }
}

export interface ProofOfPossessionMetadata {
  lifetime?: number;
  notBefore?: InnerProofOfPossessionNotBefore;
}

export interface HolderMetadata {
  clientId: string;
  pop: ProofOfPossessionMetadata;
}

export interface HolderBinder {
  nonce: string;
  verifierId: string;
}

export interface Presentation {
  format: PresentationFormat;
  payload: string;
}

export interface CredentialOfferData {}

export interface InternalPresentationRestrictionValue {
  type: PresentationRestrictionValueType;
  string?: string;
  array?: Array<Array<string>>;
}

export interface PresentationRestriction {
  fields: string[];
  value?: InternalPresentationRestrictionValue;
  optional: boolean;
}

export interface PresentationInput {
  id: string;
  format?: string;
  restrictions: PresentationRestriction[];
}

// ===== Helper classes =====

export class PresentationRestrictionValue {
  static withString(s: string): InternalPresentationRestrictionValue {
    return { type: PresentationRestrictionValueType.String, string: s };
  }

  static withPattern(s: string): InternalPresentationRestrictionValue {
    return { type: PresentationRestrictionValueType.Pattern, string: s };
  }

  static withArray(a: Array<Array<string>>): InternalPresentationRestrictionValue {
    return { type: PresentationRestrictionValueType.Array, array: a };
  }
}

export class OID4VCIStatusIssuerBuilder {
  private readonly kms: Kms;
  private readonly statusIssuerMetadata: StatusIssuerMetadata;

  constructor(kms: Kms, statusIssuerMetadata: StatusIssuerMetadata) {
    this.kms = kms;
    this.statusIssuerMetadata = statusIssuerMetadata;
  }

  build() {
    const { VcCoreStatusIssuer } = require("../../");
    return new VcCoreStatusIssuer(this.kms, this.statusIssuerMetadata);
  }
}
