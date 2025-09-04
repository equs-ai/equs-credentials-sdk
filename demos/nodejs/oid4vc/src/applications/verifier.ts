import {
  AuthorizationRequestMetadata,
  AuthorizationResponse,
  AuthorizationResponseObject,
  AuthorizationResponseType,
  AuthResponseOptions,
  CredentialVerificationMetadata,
  enableLogs,
  InMemKms,
  LocalNonceHandler,
  OID4VPVerifierBuilder,
  PassAuthRequestObject,
  PassAuthRequestObjectType,
  ReqwestHttpClient,
  TracingLogFormat,
  TracingLogLevel,
} from "@equstng/agent-sdk";
import * as express from "express";
import { urlencoded } from "express";
import { json } from "body-parser";
import { config, transactionData } from "../components/config";
import { createDidAndKeyMetadata } from "../components/utils";
import * as cors from "cors";

const SESSION_ID = "session_id";

async function main(): Promise<void> {
  await enableLogs(TracingLogFormat.Full, TracingLogLevel.Info);

  const { port, host } = config.servers.verifier;
  const kms = new InMemKms();
  const nonceHandler = new LocalNonceHandler();
  const { did, keyMetadata } = await createDidAndKeyMetadata(kms);

  const verifier = await new OID4VPVerifierBuilder(
    kms,
    nonceHandler,
    keyMetadata,
    did,
  )
    .withHttpClient(ReqwestHttpClient.insecure())
    .build();

  const appState = {
    verifier,
    authReqObjStorage: new Map(),
    presentationSessionStorage: new Map(),
  };

  const app = express();
  app.use(json());
  app.use(cors());
  app.use(urlencoded({ extended: true }));

  app.get("/request_uri", async (req, res) => {
    try {
      const responseUri = `http://${host}:${port}/present`;
      const requestUri = `http://${host}:${port}/request`;
      const state = "abc380ab-d143-4cdc-936f-43deb4b740c9";

      let authResponseOptions: AuthResponseOptions = {
        mode: "direct_post",
        type: "vp_token",
        submissionUri: responseUri,
        state,
      };

      let passAuthRequestObject: PassAuthRequestObject = {
        type: PassAuthRequestObjectType.ByReference,
        requestUri: requestUri,
      };
      let authorizationRequestMetadata: AuthorizationRequestMetadata = {
        authResponseOptions: authResponseOptions,
        passAuthRequestObject: passAuthRequestObject,
        transactionData,
      };

      const { authorizationRequestUri, session } =
        await appState.verifier.createAuthorizationRequest(
          config.resolvedPresentationQuery,
          authorizationRequestMetadata,
          null,
        );

      appState.authReqObjStorage.set(
        requestUri,
        session.authorizationRequestJwt,
      );
      appState.presentationSessionStorage.set(SESSION_ID, session);

      res.contentType("text/plain").send(authorizationRequestUri);
    } catch (e: any) {
      res.status(500).send(e.message);
    }
  });

  app.get("/request", async (req, res) => {
    try {
      const fullUrl = req.protocol + "://" + req.get("host") + req.originalUrl;
      const authReqObject = appState.authReqObjStorage.get(fullUrl);
      res.contentType("application/oauth-authz-req+jwt").send(authReqObject);
    } catch (e: any) {
      res.status(500).send(e.message);
    }
  });

  app.post("/present", async (req, res): Promise<void> => {
    try {
      console.log(`Request body: `, req.body);

      if (req.body.error) {
        res.status(200).contentType("application/json").send({
          error: `Authorization response error from holder`,
          request: req.body,
        });

        return;
      }

      const vpToken = req.body.vp_token;
      if (!vpToken) throw new Error("vp_token does not exist in request body!");

      const presentationSubmission = req.body.presentation_submission;
      if (!presentationSubmission)
        throw new Error(
          "presentation_submission does not exist in request body!",
        );
      const transactionDataHashes = req.body.transaction_data_hashes;
      const transactionDataHashesAlg = req.body.transaction_data_hashes_alg;
      if (!transactionDataHashes || !transactionDataHashesAlg)
        throw new Error("Transaction Data Response doesnt exist in the body");

      const authorizationResponseObject: AuthorizationResponseObject = {
        vpToken: JSON.parse(vpToken),
        presentationSubmission: JSON.parse(presentationSubmission),
        state: req.body.state,
        transactionDataResponse: {
          hashes: JSON.parse(transactionDataHashes),
          alg: JSON.parse(transactionDataHashesAlg),
        },
      };

      const authorizationResponse: AuthorizationResponse = {
        type: AuthorizationResponseType.Plain,
        object: authorizationResponseObject,
      };

      let credentialVerificationMetadata: CredentialVerificationMetadata = {
        transactionData,
      };
      const session = appState.presentationSessionStorage.get(SESSION_ID);
      const verifiedClaims = await appState.verifier.verifyPresentation(
        authorizationResponse,
        session,
        credentialVerificationMetadata,
      );
      console.log(`Verifier claims: `, verifiedClaims);

      res.status(200).contentType("application/json").send();
    } catch (e: any) {
      res.status(500).send();
    }
  });

  app.listen(port, host);
  console.log(`Started listening on ${host}:${port}`);
}

setImmediate(main);
