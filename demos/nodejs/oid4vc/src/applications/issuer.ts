import {
  CredentialLifetime,
  enableLogs,
  InMemKms,
  IssuanceResultType,
  LocalNonceHandler,
  OID4VCIIssuerBuilder,
  TracingLogFormat,
  TracingLogLevel,
} from "@equstng/agent-sdk";
import * as express from "express";
import { config } from "../components/config";
import { json } from "body-parser";
import * as cors from "cors";
import { createDidAndKeyMetadata } from "../components/utils";

async function main(): Promise<void> {
  await enableLogs(TracingLogFormat.Full, TracingLogLevel.Info);

  const kms = new InMemKms();
  const nonceHandler = new LocalNonceHandler();
  const { keyMetadata } = await createDidAndKeyMetadata(kms);

  const issuer = await new OID4VCIIssuerBuilder(
    kms,
    config.issuerMetadata,
    keyMetadata,
  )
    .withCredentialLifetime("SD_JWT_cred_1", CredentialLifetime.finite(3600 * 24 * 365))
    .withNonceHandler(nonceHandler)
    .build();

  const app = express();
  app.use(json());
  app.use(cors());

  app.post("/nonce", async (req, res) => {
    try {
      const result = await issuer.generateNonce();
      res.send(result);
    } catch (e: any) {
      res.status(500).send(e.message);
    }
  });

  app.post("/credential", async (req, res) => {
    const accessToken = req.header("authorization")?.split(" ")[1];
    if (!accessToken) throw new Error("Auth token is not provided");

    try {
      const result = await issuer.issueCredential(
        req.body,
        accessToken,
        config.claims,
      );

      res
        .status(result.type === IssuanceResultType.ProtocolError ? 400 : 200)
        .send(result.value);
    } catch (e: any) {
      res.status(500).send(e.message);
    }
  });

  app.get("/.well-known/openid-credential-issuer", async (req, res) => {
    try {
      const result = issuer.getIssuerMetadata();
      res.send(result);
    } catch (e: any) {
      res.status(500).send(e.message);
    }
  });

  app.get("/credential_offer", async (req, res) => {
    try {
      const result = issuer.createCredentialOffer(
        ["SD_JWT_cred_1", "SD_JWT_cred_2"],
        {
          authorization_code: { issuer_state: undefined },
        },
      );
      res.send(result);
    } catch (e: any) {
      res.status(500).send(e.message);
    }
  });

  const { port, host } = config.servers.issuer;

  app.listen(port, host);
  console.log(`Started listening on ${host}:${port}`);
}

setImmediate(main);
