import {
  createDidAndKeyMetadata,
  enableLogs,
  inMemKms,
  IssuanceResultType,
  IssuanceSession,
  localNonceGenerator,
  Oid4VciIssuerBuilder,
} from "../../../../../wrappers/nodejs";
import * as express from "express";
import {config} from "../components/config";
import {json} from "body-parser";

async function main(): Promise<void> {
    await enableLogs();

    const kms = inMemKms();
    const nonceGenerator = localNonceGenerator();
    const {keyMetadata} = await createDidAndKeyMetadata(kms);

    const issuer = await new Oid4VciIssuerBuilder(
        kms,
        nonceGenerator,
        config.issuerMetadata,
        keyMetadata,
    ).build();

    const app = express();
    app.use(json());

    const sessions = new Map<string, IssuanceSession>();

    app.post("/credential", async (req, res) => {
        const accessToken = req.header("authorization")?.split(" ")[1];
        if (!accessToken) throw new Error("Auth token is not provided");

        const session = sessions.get(accessToken) ?? {};

        try {
            const result = await issuer.issueCredential(
                req.body,
                accessToken,
                config.claims,
                session,
            );
            sessions.set(accessToken, result.session);
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
                    authorization_code: {issuer_state: undefined},
                    pre_authorized_code: undefined,
                },
            );
            res.send(result);
        } catch (e: any) {
            res.status(500).send(e.message);
        }
    });

    const {port, host} = config.servers.issuer;

    app.listen(port, host);
    console.log(`Started listening on ${host}:${port}`);
}

setImmediate(main);
