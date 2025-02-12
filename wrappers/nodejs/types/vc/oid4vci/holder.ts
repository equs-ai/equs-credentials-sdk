import { buildVciHolder, JsIssuerDiscovery, Kms, NativeKms, NativeVault, OID4VCIHolder, Vault } from "../../../";
import { getNativeOrKms } from "../../utils";

export type Oid4VciHolderParameters = {
  kms: NativeKms | Kms;
  vault: NativeVault | Vault;
  clientId: string;
  issuerDiscovery: JsIssuerDiscovery;
  redirectUrl?: string;
};

export class Oid4VciHolderBuilder {
  constructor(private readonly params: Oid4VciHolderParameters) {}

  async build(): Promise<OID4VCIHolder> {
    return await buildVciHolder(
      getNativeOrKms(this.params.kms),
      this.params.vault,
      this.params.clientId,
      this.params.issuerDiscovery,
      this.params.redirectUrl,
    );
  }
}
