import {
  AuthorizationResponse,
  AuthResponseOptions,
  InMemKms,
  LocalNonceHandler,
  OID4VPVerifierBuilder,
  PassAuthRequestObject,
  PresentationSession,
} from "../../";
import { CLAIMS, PRESENTATION_DEFINITION, PRESENTATION_QUERY, PRESENTATION_SUBMISSION, STATE, VP } from "./fixtures";
import { createDidAndKeyMetadata } from "../utils";

describe("OID4VP Verifier: ", () => {
  test("create Authorization Request by Value", async () => {
    const verifier = await buildVerifier();

    const authResponseOptions: AuthResponseOptions = {
      mode: "direct_post",
      type: "vp_token",
      submissionUri: "http://localhost:9001/response",
      state: STATE,
    };

    const authReqByValue = await verifier.createAuthorizationRequest(
      PRESENTATION_QUERY,
      authResponseOptions,
      PassAuthRequestObject.byValue(),
      null,
    );

    const decodedPayload = atob(authReqByValue.authorizationRequestJwt.split(".")[1]);
    const expected_state = JSON.parse(decodedPayload)["state"];

    expect(authReqByValue.authorizationRequestUri).toContain("request=eyJh");
    expect(authReqByValue.session.nonce?.length).toBeTruthy();
    expect(authReqByValue.session.resolvedPresentationQuery.presentation_definition).toMatchObject(
      PRESENTATION_DEFINITION,
    );
    expect(expected_state).toEqual(STATE);
  });

  test("create Authorization Request by Reference", async () => {
    const verifier = await buildVerifier();

    const authResponseOptions: AuthResponseOptions = {
      mode: "direct_post",
      type: "vp_token",
      submissionUri: "http://localhost:9001/response",
      state: STATE,
    };

    const authReqByReference = await verifier.createAuthorizationRequest(
      PRESENTATION_QUERY,
      authResponseOptions,
      PassAuthRequestObject.byReference("http://localhost:9001/request"),
      null,
    );

    expect(authReqByReference.authorizationRequestUri).toContain("request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest");
    expect(authReqByReference.session.nonce?.length).toBeTruthy();
    expect(authReqByReference.session.resolvedPresentationQuery.presentation_definition).toMatchObject(
      PRESENTATION_DEFINITION,
    );
  });

  test("verify Authorization Response", async () => {
    const verifier = await buildVerifier("did:key:zDnaefQAPFVQt9sfU63hyqYgPza2pDSXSJrPrCG5paT5eaQJb");

    const session: PresentationSession = {
      nonce: "n0NcE",
      presentation_query: PRESENTATION_QUERY,
      authorizationRequestJwt: "",
    };

    const auth_response: AuthorizationResponse = {
      vpToken: VP,
      presentationSubmission: PRESENTATION_SUBMISSION,
      state: STATE,
    };

    const claims = await verifier.verifyPresentation(auth_response, session);

    expect(claims).toEqual(CLAIMS);
  });
});

async function buildVerifier(clientId = "did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX") {
  const kms = new InMemKms();
  const nonceGenerator = new LocalNonceHandler();
  const { keyMetadata } = await createDidAndKeyMetadata(kms);

  return await new OID4VPVerifierBuilder(kms, nonceGenerator, keyMetadata, clientId).build();
}
