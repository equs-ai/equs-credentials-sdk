import {
  _PresentationSession,
  AuthorizationRequestMetadata,
  AuthorizationResponse,
  AuthorizationResponseObject,
  AuthorizationResponseType,
  AuthResponseOptions,
  CredentialVerificationMetadata,
  InMemKms,
  LocalNonceHandler,
  OID4VPVerifierBuilder,
  PassAuthRequestObjectType,
  ReqwestHttpClient,
  ResolvedPresentationQuery,
  TransactionDataResponse,
} from "../../";
import {
  CLAIMS,
  DCQL,
  PRESENTATION_DEFINITION,
  PRESENTATION_QUERY,
  PRESENTATION_QUERY_FOR_DCQL,
  PRESENTATION_SUBMISSION,
  STATE,
  VP,
} from "./fixtures";
import { createDidAndKeyMetadata } from "../utils";
import { util as jose } from "node-jose";
import { TransactionDataItem } from "../../";

describe("OID4VP Verifier: ", () => {
  it("create Authorization Request by Value", async () => {
    const verifier = await buildVerifier();

    const authResponseOptions: AuthResponseOptions = {
      mode: "direct_post",
      type: "vp_token",
      submissionUri: "http://localhost:9001/response",
      state: STATE,
    };

    const authorizationRequestMetadata: AuthorizationRequestMetadata = {
      authResponseOptions: authResponseOptions,
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByValue,
      },
    };
    const authReqByValue = await verifier.createAuthorizationRequest(
      PRESENTATION_QUERY,
      authorizationRequestMetadata,
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

  it("create Authorization Request by Value with DCQL", async () => {
    const verifier = await buildVerifier();

    const authResponseOptions: AuthResponseOptions = {
      mode: "direct_post",
      type: "vp_token",
      submissionUri: "http://localhost:9001/response",
      state: STATE,
    };

    const authorizationRequestMetadata: AuthorizationRequestMetadata = {
      authResponseOptions: authResponseOptions,
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByValue,
      },
    };
    const authReqByValue = await verifier.createAuthorizationRequest(
      PRESENTATION_QUERY_FOR_DCQL,
      authorizationRequestMetadata,
      null,
    );

    const decodedPayload = atob(authReqByValue.authorizationRequestJwt.split(".")[1]);
    const expected_state = JSON.parse(decodedPayload)["state"];

    expect(authReqByValue.authorizationRequestUri).toContain("request=eyJh");
    expect(authReqByValue.session.nonce?.length).toBeTruthy();
    expect(authReqByValue.session.resolvedPresentationQuery.dcql_query).toMatchObject(DCQL);
    expect(expected_state).toEqual(STATE);
  });

  it("create signed Authorization Request by Value with DCQL and dc_api/dc_api.jwt response mode", async () => {
    const verifier = await buildVerifier();
    const response_modes = ["dc_api", "dc_api.jwt"];

    for (const responseMode of response_modes) {
      const authResponseOptions: AuthResponseOptions = {
        mode: responseMode,
        type: "vp_token",
        state: STATE,
      };
      const expectedOrigins = ["https://example.verifier.org"];
      const authorizationRequestMetadata: AuthorizationRequestMetadata = {
        authResponseOptions: authResponseOptions,
        passAuthRequestObject: {
          type: PassAuthRequestObjectType.ByValue,
        },
        expectedOrigins: expectedOrigins,
      };

      const authReqByValue = await verifier.createAuthorizationRequest(
        PRESENTATION_QUERY_FOR_DCQL,
        authorizationRequestMetadata,
        null,
      );

      expect(authReqByValue.authorizationRequestUri).toContain("request=eyJh");
      expect(authReqByValue.session.nonce?.length).toBeTruthy();
      expect(authReqByValue.session.resolvedPresentationQuery.dcql_query).toMatchObject(DCQL);

      const decodedPayload = atob(authReqByValue.authorizationRequestJwt.split(".")[1]);
      const authReqJson = JSON.parse(decodedPayload);

      expect(authReqJson["state"]).toEqual(STATE);
      expect(authReqJson["response_mode"]).toEqual(responseMode);
      expect(authReqJson["expected_origins"]).toEqual(expectedOrigins);
      expect(authReqJson["response_uri"]).toBeFalsy();
      expect(authReqJson["redirect_uri"]).toBeFalsy();
    }
  });

  it("create Authorization Request by Reference", async () => {
    const verifier = await buildVerifier();

    const authResponseOptions: AuthResponseOptions = {
      mode: "direct_post",
      type: "vp_token",
      submissionUri: "http://localhost:9001/response",
      state: STATE,
    };

    const authorizationRequestMetadata: AuthorizationRequestMetadata = {
      authResponseOptions: authResponseOptions,
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByReference,
        requestUri: "http://localhost:9001/request",
      },
    };
    const authReqByReference = await verifier.createAuthorizationRequest(
      PRESENTATION_QUERY,
      authorizationRequestMetadata,
      null,
    );

    expect(authReqByReference.authorizationRequestUri).toContain("request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest");
    expect(authReqByReference.session.nonce?.length).toBeTruthy();
    expect(authReqByReference.session.resolvedPresentationQuery.presentation_definition).toMatchObject(
      PRESENTATION_DEFINITION,
    );
  });

  it("create Authorization Request with TransactionData", async () => {
    const verifier = await buildVerifier();

    const authResponseOptions: AuthResponseOptions = {
      mode: "direct_post",
      type: "vp_token",
      submissionUri: "http://localhost:9001/response",
      state: STATE,
    };

    const transactionData: Array<TransactionDataItem> = [
      {
        type: "some_type",
        credential_ids: ["1", "2"],
        transaction_data_hashes_alg: ["sha-256"],
      },
    ];

    const authorizationRequestMetadata: AuthorizationRequestMetadata = {
      authResponseOptions: authResponseOptions,
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByReference,
        requestUri: "http://localhost:9001/request",
      },
      transactionData,
    };

    const authReqByReference = await verifier.createAuthorizationRequest(
      PRESENTATION_QUERY,
      authorizationRequestMetadata,
      null,
    );
    const transactionDataAsBase64 =
      "eyJ0eXBlIjoic29tZV90eXBlIiwiY3JlZGVudGlhbF9pZHMiOlsiMSIsIjIiXSwidHJhbnNhY3Rpb25fZGF0YV9oYXNoZXNfYWxnIjpbInNoYS0yNTYiXX0";
    const jwt = authReqByReference.authorizationRequestJwt.split(".")[1];
    expect(jose.base64url.decode(jwt).toString()).toContain(transactionDataAsBase64);
    expect(jose.base64url.decode(jwt).toString()).toContain("transaction_data");
  });

  it("verify Authorization Response", async () => {
    const verifier = await buildVerifier("did:key:zDnaekKgXHnezLxn9UBZPEUfDhU3cM3zga2vouoCDogzFUh4J");

    const rpq: ResolvedPresentationQuery = {
      presentation_definition: PRESENTATION_QUERY.presentation_definition,
      dcql_query: PRESENTATION_QUERY.dcql_query,
    };
    const session: _PresentationSession = {
      nonce: "n0NcE",
      resolvedPresentationQuery: rpq,
      authorizationRequestJwt: "",
    };

    const auth_response_object: AuthorizationResponseObject = {
      vpToken: VP,
      presentationSubmission: PRESENTATION_SUBMISSION,
      state: STATE,
    };

    const auth_response: AuthorizationResponse = {
      type: AuthorizationResponseType.Plain,
      object: auth_response_object,
    };

    const verificationMetadata: CredentialVerificationMetadata = {};
    const claims = await verifier.verifyPresentation(auth_response, session, verificationMetadata);

    expect(claims).toEqual(CLAIMS);
  });

  it("verify Authorization Response with transaction data", async () => {
    const verifier = await buildVerifier("did:key:zDnaekKgXHnezLxn9UBZPEUfDhU3cM3zga2vouoCDogzFUh4J");

    const rpq: ResolvedPresentationQuery = {
      presentation_definition: PRESENTATION_QUERY.presentation_definition,
      dcql_query: PRESENTATION_QUERY.dcql_query,
    };
    const session: _PresentationSession = {
      nonce: "n0NcE",
      resolvedPresentationQuery: rpq,
      authorizationRequestJwt: "",
    };
    const transactionData: Array<TransactionDataItem> = [
      {
        type: "some_type",
        credential_ids: ["1", "2"],
        transaction_data_hashes_alg: ["sha-256"],
      },
    ];

    const transactionDataResponse: TransactionDataResponse = {
      hashes: ["dqpRRxJ7C1_lJuO62E3LbZ5Mgfjm4LaIMfYWutUs_14"],
    };

    const auth_response_object: AuthorizationResponseObject = {
      vpToken: VP,
      presentationSubmission: PRESENTATION_SUBMISSION,
      state: STATE,
      transactionDataResponse: transactionDataResponse,
    };

    const auth_response: AuthorizationResponse = {
      type: AuthorizationResponseType.Plain,
      object: auth_response_object,
    };

    const verificationMetadata: CredentialVerificationMetadata = {
      transactionData,
    };
    const claims = await verifier.verifyPresentation(auth_response, session, verificationMetadata);

    expect(claims).toEqual(CLAIMS);
  });
});

async function buildVerifier(clientId = "did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX") {
  const kms = new InMemKms();
  const nonceGenerator = new LocalNonceHandler();
  const { keyMetadata } = await createDidAndKeyMetadata(kms);

  return await new OID4VPVerifierBuilder(kms, nonceGenerator, keyMetadata, clientId)
    .withHttpClient(ReqwestHttpClient.insecure())
    .build();
}
