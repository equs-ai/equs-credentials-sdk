import { InMemKms, OID4VCIIssuer, OID4VCIIssuerBuilder } from "../../";
import {
  ACCESS_TOKEN,
  CLAIMS,
  CRED_DEF_ID,
  CRED_DEF_METADATA,
  CRED_OFFER,
  CRED_REQUEST,
  CRED_REQUEST_FOR_BATCH_ISSUANCE,
  GRANTS,
  ISSUER_METADATA,
  MockNonceHandler,
} from "./fixtures";
import { createDidAndKeyMetadata } from "../utils";

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
        .withCredentialLifetime(CRED_DEF_ID, 3600)
        .build();
  });

  test("retrieve Metadata", async () => {
    const issuerMetadata = issuer.getIssuerMetadata();

    expect(issuerMetadata).toMatchObject(ISSUER_METADATA);
  });

  test("retrieve Credential Definition Metadata", async () => {
    const credDefMetadata = issuer.getCredDefMetadata(CRED_REQUEST);

    expect(credDefMetadata).toMatchObject(CRED_DEF_METADATA);
  });

  test("create Credential Offer", async () => {
    const credentialOffer = issuer.createCredentialOffer([CRED_DEF_ID], GRANTS);

    expect(credentialOffer).toMatchObject({
      params: CRED_OFFER,
      url: "openid-credential-offer://?credential_offer={%22credential_issuer%22:%22http://localhost:9000%22,%22credential_configuration_ids%22:[%22IDENTITY_SD_JWT%22],%22grants%22:{%22authorization_code%22:{%22issuer_state%22:null,%22authorization_server%22:null}}}",
    });
  });

  test("generate Nonce", async () => {
    const credentialOffer = await issuer.generateNonce();

    expect(credentialOffer).toMatchObject({
      c_nonce: NONCE,
    });
  });

  test("issue Credential", async () => {
    const result = await issuer.issueCredential(CRED_REQUEST, ACCESS_TOKEN, CLAIMS);
    expect(result.value.credentials.length).toEqual(1);
    expect(result.value.credentials[0]).toBeTruthy();
  });

  test("issue multiple Credential - Batch issuance", async () => {
    const result = await issuer.issueCredential(CRED_REQUEST_FOR_BATCH_ISSUANCE, ACCESS_TOKEN, CLAIMS);
    expect(result.value.credentials.length).toEqual(2);
    expect(result.value.credentials[0]).toBeTruthy();
    expect(result.value.credentials[1]).toBeTruthy();
  });
});
