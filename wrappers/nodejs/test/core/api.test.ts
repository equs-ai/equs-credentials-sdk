import {
    createHolder,
    createIssuer,
    createVerifier,
    resolveMetadata,
    VcCoreHolder,
    VcCoreIssuer,
    VcCoreVerifier,
} from "../../index";
import {jwtDecode} from "jwt-decode";
import {Utils} from "./utils";

describe("VC::Core", () => {
    const utils = new Utils();
    let issuer: VcCoreIssuer;
    let holder: VcCoreHolder;

    beforeEach(async () => {
        issuer = createIssuer(utils.kms, await utils.getIssuerMetadata());
        holder = createHolder(utils.kms, utils.vault, {clientId: "wallet-dev"});
    });

    describe("Issuer", () => {
        it("issue credential", async () => {
            const result = await issuer.issueCredential(
                {
                    credDefId: utils.scope,
                    protocolData: undefined,
                    credOfferId: undefined,
                    proof: {
                        format: "jwt",
                        proof: "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVxTnJnR1RBV3FVVlNVRnFvWFh3bjhONThVc2JLRVpDeUUyWlk5ZFRHS3B3cyN6RG5hZXFOcmdHVEFXcVVWU1VGcW9YWHduOE41OFVzYktFWkN5RTJaWTlkVEdLcHdzIiwidHlwIjoib3BlbmlkNHZjaS1wcm9vZitqd3QifQ.eyJhdWQiOiJodHRwczovL2lzc3Vlci1iYWNrZW5kLmNvbSIsIm5iZiI6MTczNTkwMTAzNCwiaWF0IjoxNzM1OTAxMDM0LCJleHAiOjY2MTQ4NTE1MTQsIm5vbmNlIjoiS0I1MFZPbTlJLWtQTFQ5bUFBQ1Y4ZyJ9.2flsRA_XKGFm4JBpvRHkV3QKLMo81OawQHL1YQdwVRo3OnZeugQJevWz8q-_lD-fo6U9_z_KuLNt9tQr_5A5Iw",
                    },
                },
                utils.claims,
                utils.nonce,
            );

            const decoded = jwtDecode<typeof utils.claims>(result.payload);

            expect(decoded).toMatchObject({date: "09/09/1989", address: "221B Baker Street"});
        });
        it("offer credential", async () => {
            const result = issuer.offerCredential(utils.scope, undefined);

            expect(result).toMatchObject({
                issuerId: "https://issuer-backend.com",
                credDefId: utils.scope,
                content: {
                    payload: {
                        cred_def_id: utils.scope,
                        format: "SdJwtVc",
                        claims: {},
                    },
                },
            });
        });
    });

    describe("Holder", () => {
        it("request credential", async () => {
            const result = await holder.requestCredential(
                await utils.getCredentialOffer(),
                utils.nonce,
                await utils.getKeyMetadata(),
            );

            expect(result.proof.proof).toBeDefined();
        });

        it("store credential", async () => {
            const keyMetadata = await utils.getKeyMetadata();
            const credentialRequest = await holder.requestCredential(
                await utils.getCredentialOffer(),
                utils.nonce,
                keyMetadata,
            );
            const credential = await issuer.issueCredential(credentialRequest, utils.claims, utils.nonce);
            const metadata = await resolveMetadata(credential, keyMetadata);
            const result = await holder.storeCredential(credential, metadata);
            expect(result).toBeDefined();
        });

        it("verify credential", async () => {
            const credentialRequest = await holder.requestCredential(
                await utils.getCredentialOffer(),
                utils.nonce,
                await utils.getKeyMetadata(),
            );
            const credential = await issuer.issueCredential(credentialRequest, utils.claims, utils.nonce);
            const result = await holder.verifyCredential(credential);
            expect(result).toBeUndefined();
        });

        it("find vcs for presentation", async () => {
            const keyMetadata = await utils.getKeyMetadata();
            const temp_store_map = "https://credentials.example.com/identity_credential";
            const credentialRequest = await holder.requestCredential(
                await utils.getCredentialOffer(),
                utils.nonce,
                keyMetadata,
            );
            const credential = await issuer.issueCredential(credentialRequest, utils.claims, utils.nonce);
            const metadata = await resolveMetadata(credential, keyMetadata);
            await holder.storeCredential(credential, {...metadata, type: temp_store_map});

            const result = await holder.findVcsForPresentation({
                ...utils.presentationInput, restrictions: [
                    {
                        fields: ["$.vct"],
                        value: temp_store_map,
                        optional: false,
                    },
                    {
                        fields: ["$.surname"],
                        optional: false,
                    },
                ]
            });
            expect(result[0].credential.payload).toBeDefined();
        });

        it("create presentation auto", async () => {
            await requestAndStoreCredential(holder, issuer, utils);
            const result = await holder.createPresentationAuto(utils.nonce, utils.verifierId, utils.presentationInput);
            const decoded = jwtDecode<typeof utils.claims>(result.payload);

            expect(decoded).toMatchObject({address: "221B Baker Street", date: "09/09/1989"});
        });

        it("create presentation", async () => {
            await requestAndStoreCredential(holder, issuer, utils);
            const credentialEntry = await holder.findVcsForPresentation(utils.presentationInput);

            const result = await holder.createPresentation(
                utils.nonce,
                utils.verifierId,
                utils.presentationInput,
                credentialEntry[0],
            );
            const decoded = jwtDecode<typeof utils.claims>(result.payload);

            expect(decoded).toMatchObject({address: "221B Baker Street", date: "09/09/1989"});
        });
    });

    describe("Verifier", () => {
        let verifier: VcCoreVerifier;
        beforeEach(async () => {
            verifier = createVerifier(utils.verifierId);
        });

        it("verify presentation", async () => {
            await requestAndStoreCredential(holder, issuer, utils);

            const presentation = await holder.createPresentationAuto(
                utils.nonce,
                utils.verifierId,
                utils.presentationInput,
            );

            const result = await verifier.verifyPresentation(utils.nonce, presentation);
            expect(result).toMatchObject({
                address: "221B Baker Street",
                date: "09/09/1989",
                vct: "https://credentials.example.com/identity_credential",
                surname: "Doe",
            });
        });
    });
});

async function requestAndStoreCredential(holder: VcCoreHolder, issuer: VcCoreIssuer, utils: Utils): Promise<void> {
    const keyMetadata = await utils.getKeyMetadata();
    const offer = issuer.offerCredential(utils.scope);
    const credentialRequest = await holder.requestCredential(offer, utils.nonce, keyMetadata);
    const credential = await issuer.issueCredential(credentialRequest, utils.claims, utils.nonce);
    const metadata = await resolveMetadata(credential, keyMetadata);
    await holder.storeCredential(credential, metadata);
}
