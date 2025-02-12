import { inMemKms, localNonceGenerator, OID4VCIIssuer, Oid4VciIssuerBuilder } from "../../";
import {
  ACCESS_TOKEN,
  CLAIMS,
  CRED_DEF_ID,
  CRED_DEF_METADATA,
  CRED_OFFER,
  CRED_REQUEST,
  GRANTS,
  ISSUER_METADATA,
} from "./fixtures";
import { createDidAndKeyMetadata } from "../utils/utils";

describe("OID4VCI Issuer: ", () => {
  let issuer: OID4VCIIssuer;

  beforeEach(async () => {
    const kms = inMemKms();
    const nonce_generator = localNonceGenerator();
    const { keyMetadata } = await createDidAndKeyMetadata(kms);

    issuer = await new Oid4VciIssuerBuilder(kms, nonce_generator, ISSUER_METADATA, keyMetadata).build();
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

  test("issue Credential", async () => {
    const session = {
      nonce: {
        nonce: "KB50VOm9I-kPLT9mAACV8g",
        expiresIn: 864484848,
        created: 1728843957,
      },
    };

    const result = await issuer.issueCredential(CRED_REQUEST, ACCESS_TOKEN, CLAIMS, session);
    expect(result.value.credential?.length).toBeTruthy();
  });
});
