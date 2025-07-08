import { HttpRequest, HttpResponse, InMemKms, OID4VCIIssuer, OID4VCIIssuerBuilder } from "../../";
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
} from "./fixtures";
import { createDidAndKeyMetadata } from "../utils";
import { jwtDecode } from "jwt-decode";

describe("OID4VCI Issuer: ", () => {
  let issuer: OID4VCIIssuer;
  const NONCE = "KB50VOm9I-kPLT9mAACV8g";

  beforeEach(async () => {
    const kms = new InMemKms();
    const mockNonceHandler = new MockNonceHandler(NONCE);
    const { keyMetadata } = await createDidAndKeyMetadata(kms);

    issuer = await new OID4VCIIssuerBuilder(kms, ISSUER_METADATA, keyMetadata)
      .withNonceHandler(mockNonceHandler)
      .withDefaultCredentialLifetime(3600 * 24)
      .withCredentialLifetime(CredDefId1, 3600 * 24 * 365)
      .withCredentialLifetime(CredDefId2, 3600 * 24 * 365 * 5)
      .build();
  });

  // todo enable when custom http client providing will work
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
      .withDefaultCredentialLifetime(3600 * 24)
      .withCredentialLifetime(CredDefId1, 3600)
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
      url: "openid-credential-offer://?credential_offer={%22credential_issuer%22:%22http://localhost:9000%22,%22credential_configuration_ids%22:[%22IDENTITY_SD_JWT_1%22],%22grants%22:{%22authorization_code%22:{%22issuer_state%22:null,%22authorization_server%22:null}}}",
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
    expect(credential2.exp * 1000 - Date.now()).toBeGreaterThan(5 * 364 * 24 * 60 * 60 * 1000);
  });

  it("issue multiple Credential - Batch issuance", async () => {
    const result = await issuer.issueCredential(CRED_REQUEST_FOR_BATCH_ISSUANCE, ACCESS_TOKEN, CLAIMS);
    expect(result.value.credentials.length).toEqual(2);
    expect(result.value.credentials[0]).toBeTruthy();
    expect(result.value.credentials[1]).toBeTruthy();
  });
});
