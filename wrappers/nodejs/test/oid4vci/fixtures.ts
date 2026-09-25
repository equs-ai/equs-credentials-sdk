import {
  Alg,
  AuthMetadata,
  Claims,
  CredentialDefinitionFormat,
  CredentialFormats,
  CredentialOfferGrants,
  InMemKms,
  InMemVault,
  IssuerMetadata,
  JwkAlgorithm,
  NonceHandler,
  OID4VCICredentialMetadata,
  OID4VCICredentialOffer,
  OID4VCICredentialRequest,
  OID4VCIIssuerMetadata,
  ReqwestHttpClient,
  UniversalDIDResolver,
  VcCoreHolder,
  VcCoreIssuer,
  VCFormat,
} from "../../";
import { token } from "../../../test/js_common/test/bundle";
import { createDidAndKeyMetadata } from "../utils";

export const IssuerEndpoint = "http://localhost:9000";
export const TokenEndpoint = `${IssuerEndpoint}/auth/token`;
export const PushedAuthRequestEndpoint = `${IssuerEndpoint}/auth/par/request`;
export const CredDefId1 = "IDENTITY_SD_JWT_1";
export const CredDefId2 = "IDENTITY_SD_JWT_2";
export const CredType = "SD_JWT_cred";
export const Scope = "SD_JWT_cred";

const CredentialDefinition = {
  format: CredentialFormats.VCSDJWT,
  scope: Scope,
  cryptographic_binding_methods_supported: ["jwk"],
  credential_signing_alg_values_supported: [JwkAlgorithm.ES256],
  proof_types_supported: {
    jwt: {
      proof_signing_alg_values_supported: ["ES256"],
    },
  },
  vct: CredType,
  credential_metadata: {
    claims: [
      {
        path: ["given_name"],
        display: [{ name: "Name" }],
        mandatory: true,
      },
      {
        path: ["family_name"],
        display: [{ name: "Surname" }],
        mandatory: true,
      },
      {
        path: ["dob"],
        display: [{ name: "Date of birth" }],
        mandatory: true,
      },
    ],
  },
} satisfies OID4VCICredentialMetadata;

export const ISSUER_METADATA: OID4VCIIssuerMetadata = {
  credential_issuer: IssuerEndpoint,
  authorization_servers: [`${IssuerEndpoint}/auth`],
  credential_endpoint: `${IssuerEndpoint}/credential`,
  batch_credential_issuance: {
    batch_size: 2,
  },
  credential_configurations_supported: {
    [CredDefId1]: CredentialDefinition,
    [CredDefId2]: CredentialDefinition,
  },
};

export const AUTH_SERVER_METADATA: AuthMetadata = {
  issuer: `${IssuerEndpoint}/auth`,
  authorization_endpoint: `${IssuerEndpoint}/auth`,
  token_endpoint: TokenEndpoint,
  introspection_endpoint: `${IssuerEndpoint}/auth/introspection`,
  jwks_uri: `${IssuerEndpoint}/auth/jwks`,
  grant_types_supported: ["authorization_code"],
  response_types_supported: ["code", "token"],
  subject_types_supported: ["public"],
  id_token_signing_alg_values_supported: ["ES256"],
  pushed_authorization_request_endpoint: PushedAuthRequestEndpoint,
};

export const CRED_DEF_METADATA: OID4VCICredentialMetadata = {
  scope: Scope,
  cryptographic_binding_methods_supported: ["jwk"],
  proof_types_supported: {
    jwt: {
      proof_signing_alg_values_supported: ["ES256"],
    },
  },
  format: CredentialFormats.VCSDJWT,
  credential_signing_alg_values_supported: [JwkAlgorithm.ES256],
  vct: "SD_JWT_cred",
  credential_metadata: {
    claims: [
      {
        path: ["given_name"],
        display: [{ name: "Name" }],
        mandatory: true,
      },
      {
        path: ["family_name"],
        display: [{ name: "Surname" }],
        mandatory: true,
      },
      {
        path: ["dob"],
        display: [{ name: "Date of birth" }],
        mandatory: true,
      },
    ],
  },
};

/**
 * Mints a fresh OID4VCI proof-of-possession JWT bound to `nonce`, with `aud`
 * matching {@link IssuerEndpoint} — the generic bundle `proofJwt` carries a
 * fixed `aud` (`https://issuer.example`) that doesn't match this issuer's
 * own endpoint, so it can't stand in here. `VcCoreHolder.requestCredential`
 * derives `aud` from the offer it's given, so a throwaway `VcCoreIssuer`
 * configured with this endpoint produces a request whose proof already
 * carries the right audience.
 */
export async function buildProofJwt(nonce: string): Promise<string> {
  const issuerKms = new InMemKms();
  const { keyMetadata: issuerKeyMetadata } = await createDidAndKeyMetadata(issuerKms);
  const issuerMetadata: IssuerMetadata = {
    issuerId: IssuerEndpoint,
    credDefs: [
      {
        credDefId: CredDefId1,
        format: VCFormat.SdJwtVc,
        claims: {},
        supportedProofs: { Jwt: ["ES256"] },
        supportedSigningAlgs: [Alg.ES256],
        display: undefined,
        protocolData: {
          format: CredentialDefinitionFormat.SdJwt,
          payload: { vct: CredType, disclosures: ["$.given_name"] },
        },
        keyMetadata: issuerKeyMetadata,
      },
    ],
    protocolData: undefined,
  };
  const issuer = new VcCoreIssuer(issuerKms, issuerMetadata, new UniversalDIDResolver());
  const offer = issuer.offerCredential(CredDefId1, undefined);

  const holderKms = new InMemKms();
  const { keyMetadata: holderKeyMetadata } = await createDidAndKeyMetadata(holderKms);
  const holder = new VcCoreHolder(
    holderKms,
    new InMemVault(),
    { clientId: "wallet-dev", pop: { lifetime: 300 } },
    new UniversalDIDResolver(),
    ReqwestHttpClient.insecure(),
  );
  const request = await holder.requestCredential(offer, nonce, holderKeyMetadata);
  return request.proof.proof;
}

export async function buildCredRequest(credDefId: string, nonce: string): Promise<OID4VCICredentialRequest> {
  const proofJwt = await buildProofJwt(nonce);
  return {
    credential_configuration_id: credDefId,
    proofs: { jwt: [proofJwt] },
    credential_response_encryption: null,
  };
}

export async function buildBatchCredRequest(nonce: string): Promise<OID4VCICredentialRequest> {
  const proofJwt = await buildProofJwt(nonce);
  return {
    credential_configuration_id: CredDefId1,
    proofs: { jwt: [proofJwt, proofJwt] },
    credential_response_encryption: null,
  };
}

export const GRANTS: CredentialOfferGrants = {
  authorization_code: {
  },
};

export const CRED_OFFER: OID4VCICredentialOffer = {
  credential_issuer: IssuerEndpoint,
  credential_configuration_ids: [CredDefId1],
  grants: GRANTS,
};

export const ACCESS_TOKEN = token("accessToken");

export const CODE_RESPONSE = {
  request_uri: "urn:ietf:params:oauth:request_uri:code",
  expires_in: 86400,
};

export const ACCESS_TOKEN_RESPONSE = {
  access_token: ACCESS_TOKEN,
  token_type: "bearer",
  expires_in: 86400,
};

export const CLAIMS: Claims = {
  vct: "SD_JWT_cred",
  given_name: "John",
  family_name: "Doe",
  dob: "09/09/1989",
};

export const SD_JWT_CREDS = token("sdJwtCreds");

export const CRED_RESPONSE = {
  format: "dc+sd-jwt",
  credential: SD_JWT_CREDS,
  notification_id: "1111",
};

export const CRED_OFFER_WITH_PRE_AUTH_GRANT: OID4VCICredentialOffer = {
  credential_issuer: IssuerEndpoint,
  credential_configuration_ids: [CredDefId1],
  grants: {
    "urn:ietf:params:oauth:grant-type:pre-authorized_code": {
      "pre-authorized_code": "code",
      tx_code: null,
      interval: null,
      authorization_server: `${IssuerEndpoint}/auth`,
    },
  },
};

export const CRED_OFFER_WITH_AUTH_GRANT: OID4VCICredentialOffer = {
  credential_issuer: IssuerEndpoint,
  credential_configuration_ids: [CredDefId1],
  grants: {
    authorization_code: {
      issuer_state: "state",
    },
  },
};

export class MockNonceHandler implements NonceHandler {
  /** The nonces of each `invalidate` call, in call order. */
  readonly invalidated: Array<Array<string>> = [];

  constructor(private readonly nonce: string) {
    this.generate = this.generate.bind(this);
    this.validate = this.validate.bind(this);
    this.invalidate = this.invalidate.bind(this);
  }

  async generate(): Promise<string> {
    return this.nonce;
  }

  async validate(nonce: string): Promise<boolean> {
    return true;
  }

  async invalidate(nonces: Array<string>): Promise<void> {
    this.invalidated.push(nonces);
  }
}
