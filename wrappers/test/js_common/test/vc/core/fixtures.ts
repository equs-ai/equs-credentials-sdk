import {
  Alg,
  CredentialDefinitionFormat,
  CredentialStatusInfoFormat,
  DIDKey,
  InMemKms,
  InMemVault,
  IssuerMetadata,
  KeyType,
  PresentationInput,
  PresentationRestrictionValue,
  StatusIssuerMetadata,
  StatusListFormatFmt,
  UniversalDIDResolver,
  VcCoreIssuer,
  VCFormat,
  VCStatusesDataFormat,
  type KeyMetadata,
} from "agent-sdk";

export class Utils {
  readonly nonce = "KB50VOm9I-kPLT9mAACV8g";
  readonly verifierId = "Verifier-id";
  readonly scope = "SD_JWT_cred_sample";
  readonly kms = new InMemKms();
  readonly vault = new InMemVault();
  readonly credStatusInfo = {
    format: CredentialStatusInfoFormat.TokenStatusList,
    payload: {
      idx: 1,
      uri: "http://localhost:9001/status_list",
    },
  };

  get claims() {
    return {
      name: "John",
      surname: "Doe",
      address: "221B Baker Street",
      date: "09/09/1989",
    };
  }

  get presentationInput(): PresentationInput {
    return {
      id: this.scope,
      format: "dc+sd-jwt",
      restrictions: [
        {
          fields: ["$.vct"],
          value: PresentationRestrictionValue.withString("https://credentials.example.com/identity_credential"),
          optional: false,
        },
        {
          fields: ["$.surname"],
          optional: false,
        },
      ],
    };
  }

  async getKeyMetadata(): Promise<KeyMetadata> {
    const kms = this.kms;
    const keyId = await kms.create(KeyType.P256);
    const keyHandle = await kms.get(keyId);
    const didKey = new DIDKey();
    const did = didKey.generate(keyHandle);
    const resolver = new UniversalDIDResolver();
    const vm = await resolver.resolveVerificationMethod(did);
    return { didUrl: vm.id, kid: keyId };
  }

  async getStatusIssuerMetadata(): Promise<StatusIssuerMetadata> {
    return {
      issuerId: "test",
      supportedStatusLists: [
        {
          id: "test_status_list",
          format: {
            format: StatusListFormatFmt.StatusListTokenJwt,
            payload: {
              statuses_nr: 32,
              status_list_url: "http://localhost:9001/status_list",
              status_size: 2,
            },
          },
          keyMetadata: await this.getKeyMetadata(),
        },
      ],
    };
  }

  async getIssuerMetadata(): Promise<IssuerMetadata> {
    return {
      issuerId: "https://issuer-backend.com",
      credDefs: [
        {
          credDefId: this.scope,
          format: VCFormat.SdJwtVc,
          claims: {},
          supportedProofs: { Jwt: ["ES256"] },
          supportedSigningAlgs: [Alg.ES256, Alg.EdDSA],
          display: undefined,
          protocolData: {
            format: CredentialDefinitionFormat.SdJwt,
            payload: {
              vct: "https://credentials.example.com/identity_credential",
              disclosures: ["$.name", "$.surname"],
              lifetime: 10 * 60 * 1000,
            },
          },
          keyMetadata: await this.getKeyMetadata(),
        },
      ],
      protocolData: undefined,
    };
  }

  async getVCStatusesData(statuses: Record<string, number> = { "1": 0 }) {
    return {
      format: VCStatusesDataFormat.StatusListToken,
      payload: { statuses },
    };
  }

  async getCredentialOffer() {
    const issuer = new VcCoreIssuer(this.kms, await this.getIssuerMetadata(), new UniversalDIDResolver());
    return issuer.offerCredential(this.scope, undefined);
  }

  async truncateVault(): Promise<void> {
    const creds = await this.vault.getCredentials();
    for (const cred of creds) {
      await this.vault.deleteCredential(cred.id);
    }
  }
}
