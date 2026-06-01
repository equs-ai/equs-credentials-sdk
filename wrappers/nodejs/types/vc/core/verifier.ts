import {
  _VcCoreVerifier,
  Claims,
  HolderBinder,
  HttpClient,
  Presentation,
  ReqwestHttpClient,
  VCStatus,
  UniversalDIDResolver,
} from "../../..";
import { contextEnsuredHttpClient } from "../../";

export class VcCoreVerifier {
  private readonly inner: _VcCoreVerifier;

  constructor(verifierId: string, didResolver: UniversalDIDResolver) {
    this.inner = new _VcCoreVerifier(verifierId, didResolver.inner);
  }

  async verifyPresentation(
    holderBinder: HolderBinder | null | undefined,
    presentation: Presentation,
    httpClient: ReqwestHttpClient,
  ): Promise<Claims> {
    return this.inner.verifyPresentation(holderBinder, presentation, httpClient);
  }

  async obtainCredentialStatus(presentation: Presentation, httpClient: HttpClient): Promise<VCStatus | null> {
    return this.inner.obtainCredentialStatus(presentation, contextEnsuredHttpClient(httpClient));
  }
}
