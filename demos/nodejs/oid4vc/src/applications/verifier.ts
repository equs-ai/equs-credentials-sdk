import {
    createDidAndKeyMetadata,
    enableLogs,
    inMemKms,
    localNonceGenerator,
    Oid4VpVerifierBuilder,
    PassAuthRequestObject,
} from "../../../../../wrappers/nodejs";
import * as express from "express";
import {urlencoded} from "express";
import {json} from "body-parser";
import {config} from "../components/config";

async function main(): Promise<void> {
    await enableLogs();

    const {port, host} = config.servers.verifier;
    const kms = inMemKms();
    const nonceGenerator = localNonceGenerator();
    const {did, keyMetadata} = await createDidAndKeyMetadata(kms);

    const appState = {
        verifier: await new Oid4VpVerifierBuilder(
            kms,
            nonceGenerator,
            keyMetadata,
            did,
        ).build(),
        authReqObjStorage: new Map(),
        presentationSessionStorage: new Map(),
    };

    const app = express();
    app.use(json());
    app.use(urlencoded({extended: true}));

    app.get("/request_uri", async (req, res) => {
        try {
            const responseUri = `http://${host}:${port}/present`;
            const requestUri = `http://${host}:${port}/request`;

            let authResponseOptions = {
                mode: "direct_post",
                type: "vp_token",
                submissionUri: responseUri,
            }

            const {authorizationRequestUri, session} =
                await appState.verifier.createAuthorizationRequest(
                    config.presentationDefinition,
                    authResponseOptions,
                    PassAuthRequestObject.byReference(requestUri),
                    null
                );

            res.contentType("text/plain").send(authorizationRequestUri);
        } catch (e: any) {
            res.status(500).send(e.message);
        }
    });

    app.get("/request", async (req, res) => {
        try {
            const fullUrl = req.protocol + "://" + req.get("host") + req.originalUrl;
            const authReqObject = appState.authReqObjStorage.get(fullUrl);
            res.contentType("text/plain").send(authReqObject);
        } catch (e: any) {
            res.status(500).send(e.message);
        }
    });

    app.post("/present", async (req, res) => {
        try {
            const vpToken = req.body.vp_token;
            if (!vpToken) throw new Error("vp_token does not exist in request body!");

            const presentationSubmission = req.body.presentation_submission;
            if (!presentationSubmission)
                throw new Error(
                    "presentation_submission does not exist in request body!",
                );

            const authorizationResponse = {
                vpToken: JSON.parse(vpToken),
                presentationSubmission: JSON.parse(presentationSubmission),
            };

            const session = appState.presentationSessionStorage.get(
                authorizationResponse.presentationSubmission.definition_id,
            );
            const verifiedClaims = await appState.verifier.verifyPresentation(
                authorizationResponse,
                session,
            );
            console.log(`Verifier claims: `, verifiedClaims);

            res.send();
        } catch (e: any) {
            res.status(500).send(e.message);
        }
    });

    app.listen(port, host);
    console.log(`Started listening on ${host}:${port}`);
}

setImmediate(main);
