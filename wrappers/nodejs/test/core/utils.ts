import {
  Alg,
  contextEnsuredKms,
  contextEnsuredVault,
  CredentialDefinitionFormat,
  CredentialOfferContentFormat,
  CredentialStatusInfoFormat,
  InMemKms,
  InMemVault,
  IssuerMetadata,
  PresentationInput,
  PresentationRestrictionValue,
  StatusIssuerMetadata,
  StatusListFormatFmt,
  VCFormat,
} from "../../";
import { createDidAndKeyMetadata } from "../utils";

export class Utils {
  readonly nonce = "KB50VOm9I-kPLT9mAACV8g";
  readonly verifierId = "Verifier-id";
  readonly scope = "SD_JWT_cred_sample";
  readonly kms = contextEnsuredKms(new InMemKms());
  readonly vault = contextEnsuredVault(new InMemVault());
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

  async getKeyMetadata() {
    return (await createDidAndKeyMetadata(this.kms)).keyMetadata;
  }

  async getCredentialOffer() {
    const keyMetadata = await this.getKeyMetadata();
    return {
      content: {
        format: CredentialOfferContentFormat.CredDef,
        payload: {
          cred_def_id: "",
          format: "SdJwtVc",
          claims: {},
          supported_proofs: undefined,
          supported_signing_algs: undefined,
          display: undefined,
          protocol_data: undefined,
          key_metadata: {
            didUrl: keyMetadata.didUrl,
            kid: keyMetadata.kid,
          },
        },
      },
      credDefId: this.scope,
      credOfferId: undefined,
      issuerId: "https://issuer-backend.com",
      params: {},
      protocolData: undefined,
      url: "http://localhost:35001",
    };
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
              status_size: 1,
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
}
