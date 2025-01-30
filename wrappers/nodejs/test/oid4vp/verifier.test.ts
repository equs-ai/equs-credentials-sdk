import { inMemKms, localNonceGenerator, Oid4VpVerifierBuilder, PassAuthRequestObject } from "../../index.js";
import { CLAIMS, PRESENTATION_DEFINITION, PRESENTATION_SUBMISSION, VP } from "./fixtures";
import { createDidAndKeyMetadata } from "../utils/utils";

describe("OID4VP Verifier: ", () => {
  test("create Authorization Request", async () => {
    const verifier = await buildVerifier();

    let authResponseOptions = {
      mode: "direct_post",
      type: "vp_token",
      submissionUri: "http://localhost:9001/response",
    };

    let authReqByValue = await verifier.createAuthorizationRequest(
      PRESENTATION_DEFINITION,
      authResponseOptions,
      PassAuthRequestObject.byValue(),
      null,
    );

    expect(authReqByValue.authorizationRequestUri).toContain("request=eyJh");
    expect(authReqByValue.session.nonce?.length).toBeTruthy();
    expect(authReqByValue.session.presentationDefinition).toMatchObject(PRESENTATION_DEFINITION);

    let authReqByReference = await verifier.createAuthorizationRequest(
      PRESENTATION_DEFINITION,
      authResponseOptions,
      PassAuthRequestObject.byReference("http://localhost:9001/request"),
      null,
    );

    expect(authReqByReference.authorizationRequestUri).toContain("request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest");
    expect(authReqByReference.session.nonce?.length).toBeTruthy();
    expect(authReqByReference.session.presentationDefinition).toMatchObject(PRESENTATION_DEFINITION);
  });

  test("verify Authorization Response", async () => {
    const verifier = await buildVerifier("did:key:zDnaefQAPFVQt9sfU63hyqYgPza2pDSXSJrPrCG5paT5eaQJb");

    const session = {
      nonce: "n0NcE",
      presentationDefinition: PRESENTATION_DEFINITION,
      authorizationRequestJwt: "",
    };

    const auth_request = {
      vpToken: VP,
      presentationSubmission: PRESENTATION_SUBMISSION,
    };

    const claims = await verifier.verifyPresentation(auth_request, session);

    expect(claims).toEqual(CLAIMS);
  });
});

async function buildVerifier(client_id = "did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX") {
  let kms = inMemKms();
  let nonce_generator = localNonceGenerator();
  let { keyMetadata } = await createDidAndKeyMetadata(kms);

  return await new Oid4VpVerifierBuilder(kms, nonce_generator, keyMetadata, client_id).build();
}
