import { _VcCoreStatusIssuer, Kms, StatusIssuerMetadata, StatusList, VCStatusesData } from "../../..";
import { contextEnsuredKms } from "../../utils";

export class VcCoreStatusIssuer {
  private readonly inner: _VcCoreStatusIssuer;

  constructor(kms: Kms, metadata: StatusIssuerMetadata) {
    this.inner = new _VcCoreStatusIssuer(contextEnsuredKms(kms), metadata);
  }

  async issueStatusList(statusListId: string, statuses: VCStatusesData): Promise<StatusList> {
    return this.inner.issueStatusList(statusListId, statuses);
  }
}
