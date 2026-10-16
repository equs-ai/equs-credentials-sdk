import { Kms, StatusIssuerMetadata, VcCoreStatusIssuer } from "../../../";
import { contextEnsuredKms } from "../../utils";

/**
  Context safe Builder for VcCoreStatusIssuer.
 **/
export class OID4VCIStatusIssuerBuilder {
  private readonly kms: Kms;
  private readonly statusIssuerMetadata: StatusIssuerMetadata;

  constructor(kms: Kms, statusIssuerMetadata: StatusIssuerMetadata) {
    this.kms = kms;
    this.statusIssuerMetadata = statusIssuerMetadata;
  }

  build(): VcCoreStatusIssuer {
    return new VcCoreStatusIssuer(contextEnsuredKms(this.kms), this.statusIssuerMetadata);
  }
}
