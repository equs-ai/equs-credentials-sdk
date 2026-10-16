import {
  CredentialLifetime,
  HttpRequest,
  HttpResponse,
  InMemKms,
  NonceHandler,
  OID4VCIIssuer,
  OID4VCIIssuerBuilder,
} from "../../";
import {
  ACCESS_TOKEN,
  CLAIMS,
  CRED_DEF_METADATA,
  CRED_OFFER,
  CRED_REQUEST_FOR_BATCH_ISSUANCE,
  CredDefId1,
  CredDefId2,
  CredRequest1,
  CredRequest2,
  GRANTS,
  ISSUER_METADATA,
  MockNonceHandler,
  PROOF_JWT,
} from "./fixtures";
import { createDidAndKeyMetadata } from "../utils";
import { jwtDecode } from "jwt-decode";

describe("OID4VCI Issuer: ", () => {
  let issuer: OID4VCIIssuer;
  let nonceHandler: MockNonceHandler;
  const NONCE = "KB50VOm9I-kPLT9mAACV8g";

  beforeEach(async () => {
    const kms = new InMemKms();
    nonceHandler = new MockNonceHandler(NONCE);
    const { keyMetadata } = await createDidAndKeyMetadata(kms);

    issuer = await new OID4VCIIssuerBuilder(kms, ISSUER_METADATA, keyMetadata)
      .withNonceHandler(nonceHandler)
      .withDefaultCredentialLifetime(CredentialLifetime.infinite())
      .withCredentialLifetime(CredDefId1, CredentialLifetime.finite(3600 * 24 * 365))
      // CredDefId2 lifetime must fallback to default (infinite).
      .build();
  });

  test.skip("Custom http client", async () => {
    const kms = new InMemKms();
    const mockNonceHandler = new MockNonceHandler(NONCE);
    const { keyMetadata } = await createDidAndKeyMetadata(kms);
    let result: HttpResponse;
    const httpClient = {
      asyncCall: async (request: HttpRequest) => {
        result = {
          statusCode: 200,
          headers: {},
          body: "success",
        };
        return result;
      },
    };

    issuer = await new OID4VCIIssuerBuilder(kms, ISSUER_METADATA, keyMetadata)
      .withNonceHandler(mockNonceHandler)
      .withDefaultCredentialLifetime(CredentialLifetime.finite(3600 * 24 * 365))
      .withCredentialLifetime(CredDefId1, CredentialLifetime.finite(3600))
      .withHttpClient(httpClient)
      .tokenValidationJwks("https://google.com")
      .build();

    await issuer.issueCredential(CredRequest1, ACCESS_TOKEN, CLAIMS);

    expect(result).toEqual({
      statusCode: 200,
      headers: {},
      body: "success",
    });
  });

  it("validate token", async () => {
    const issuerMetadata = issuer.getIssuerMetadata();

    expect(issuerMetadata).toMatchObject(ISSUER_METADATA);
  });

  it("retrieve Metadata", async () => {
    const issuerMetadata = issuer.getIssuerMetadata();

    expect(issuerMetadata).toMatchObject(ISSUER_METADATA);
  });

  it("retrieve Credential Definition Metadata", async () => {
    const credDefMetadata = issuer.getCredDefMetadata(CredRequest1);

    expect(credDefMetadata).toMatchObject(CRED_DEF_METADATA);
  });

  it("create Credential Offer", async () => {
    const credentialOffer = issuer.createCredentialOffer([CredDefId1], GRANTS);

    expect(credentialOffer).toMatchObject({
      params: CRED_OFFER,
      url: "openid-credential-offer://?credential_offer={%22credential_issuer%22:%22http://localhost:9000%22,%22credential_configuration_ids%22:[%22IDENTITY_SD_JWT_1%22],%22grants%22:{%22authorization_code%22:{}}}",
    });
  });

  it("generate Nonce", async () => {
    const credentialOffer = await issuer.generateNonce();

    expect(credentialOffer).toMatchObject({
      c_nonce: NONCE,
    });
  });

  it("issue Credential", async () => {
    const result1 = await issuer.issueCredential(CredRequest1, ACCESS_TOKEN, CLAIMS);
    const result2 = await issuer.issueCredential(CredRequest2, ACCESS_TOKEN, CLAIMS);
    const credential1 = jwtDecode(result1.value.credentials[0].credential);
    const credential2 = jwtDecode(result2.value.credentials[0].credential);

    expect(credential1.exp * 1000 - Date.now()).toBeGreaterThan(364 * 24 * 60 * 60 * 1000);
    expect(credential2.exp).toBeUndefined();
  });

  it("issue multiple Credential - Batch issuance", async () => {
    const result = await issuer.issueCredential(CRED_REQUEST_FOR_BATCH_ISSUANCE, ACCESS_TOKEN, CLAIMS);
    expect(result.value.credentials.length).toEqual(2);
    expect(result.value.credentials[0]).toBeTruthy();
    expect(result.value.credentials[1]).toBeTruthy();
  });

  it("issue multiple Credential - spends the shared nonce once", async () => {
    await issuer.issueCredential(CRED_REQUEST_FOR_BATCH_ISSUANCE, ACCESS_TOKEN, CLAIMS);

    expect(nonceHandler.invalidated).toEqual([[NONCE]]);
  });

  it("issue multiple Credential - spends the nonce through a handler that only has prototype methods", async () => {
    // The shape a DI framework produces: methods live on the prototype, nothing is bound in the
    // constructor. `invalidate` has to be picked up all the same.
    const invalidated: Array<Array<string>> = [];

    class PrototypeNonceHandler implements NonceHandler {
      async generate(): Promise<string> {
        return NONCE;
      }

      async validate(nonce: string): Promise<boolean> {
        return true;
      }

      async invalidate(nonces: Array<string>): Promise<void> {
        invalidated.push(nonces);
      }
    }

    const kms = new InMemKms();
    const { keyMetadata } = await createDidAndKeyMetadata(kms);
    const issuerWithPrototypeHandler = await new OID4VCIIssuerBuilder(kms, ISSUER_METADATA, keyMetadata)
      .withNonceHandler(new PrototypeNonceHandler())
      .withDefaultCredentialLifetime(CredentialLifetime.infinite())
      .build();

    await issuerWithPrototypeHandler.issueCredential(CRED_REQUEST_FOR_BATCH_ISSUANCE, ACCESS_TOKEN, CLAIMS);

    expect(invalidated).toEqual([[NONCE]]);
  });

  it("issue Credential - spends the nonce of a rejected request", async () => {
    const request = {
      ...CRED_REQUEST_FOR_BATCH_ISSUANCE,
      proofs: { jwt: [PROOF_JWT, "not-a-key-proof"] },
    };

    const result = await issuer.issueCredential(request, ACCESS_TOKEN, CLAIMS);

    expect(result.value).toMatchObject({ error: "invalid_proof" });
    // The second key proof is rejected, but the nonce the first one was validated against is spent
    // all the same — a rejected request must leave no nonce behind to retry with.
    expect(nonceHandler.invalidated).toEqual([[NONCE]]);
  });
});
