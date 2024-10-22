import test from "ava";
import mockttp from "mockttp";
import {createDidAndKeyMetadata, inMemKms, inMemVault, Oid4VpHolderBuilder, VCFormat} from "../../index.js";
import {AUTH_REQUEST, AUTH_REQUEST_JWT, VC, VC_TYPE} from "./fixtures.mjs";
import {isEmpty} from "../utils.mjs";

const mockServer = mockttp.getLocal()

test.beforeEach(_ => mockServer.start(9001));

test.afterEach(_ => mockServer.stop());

test.serial('resolve Authorization request', async t => {
    await mockServer.forGet('/request').thenReply(200, AUTH_REQUEST_JWT, {"content-type": "text/plain"})

    const vpHolder = await buildHolder()

    const authorizationRequest = await vpHolder.getAuthorizationRequest(
        'openid4vp://?client_id=did%3Akey%3AzDnaesEX79GFQf4cX9wKxbWHBJepu5jHe53WRnasdhWgZ8FKR&request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest'
    );
    t.like(authorizationRequest, AUTH_REQUEST)
})

test.serial('present Credentials Auto', async t => {
    await mockServer.forPost('/response').thenCallback(async (request) => {
        const form_data = await request.body.getFormData()

        t.true(!isEmpty(form_data.presentation_submission))
        t.true(!isEmpty(form_data.vp_token))

        return {statusCode: 200, body: ""}
    })

    const kms = inMemKms();
    const vault = inMemVault()
    const vpHolder = await buildHolder(kms, vault)

    const {keyMetadata} = await createDidAndKeyMetadata(kms)
    const credential = {
        format: VCFormat.SdJwtVc,
        payload: VC,
    }
    const metadata = {
        type: VC_TYPE,
        kid: keyMetadata.kid,
        format: VCFormat.SdJwtVc,
        tags: [],
    }
    await vault.storeCredential(credential, metadata)

    let authRequest = AUTH_REQUEST
    authRequest.responseUri = 'http://localhost:9001/response'

    await vpHolder.presentCredentialsAuto(authRequest)
})

test.serial('present Credentials', async t => {
    await mockServer.forPost('/response').thenCallback(async (request) => {
        const form_data = await request.body.getFormData()

        t.true(!isEmpty(form_data.presentation_submission))
        t.true(!isEmpty(form_data.vp_token))

        return {statusCode: 200, body: ""}
    })

    const kms = inMemKms();
    const vault = inMemVault()
    const vpHolder = await buildHolder(kms, vault)

    const {keyMetadata} = await createDidAndKeyMetadata(kms)
    const credential = {
        format: VCFormat.SdJwtVc,
        payload: VC,
    }
    const metadata = {
        type: VC_TYPE,
        kid: keyMetadata.kid,
        format: VCFormat.SdJwtVc,
        tags: [],
    }
    await vault.storeCredential(credential, metadata)

    let authRequest = AUTH_REQUEST
    authRequest.responseUri = 'http://localhost:9001/response'

    let mapping = await vpHolder.findVcsForPresentation(authRequest)

    await vpHolder.presentCredentials(authRequest, mapping)
})

async function buildHolder(kms = inMemKms(), vault = inMemVault()) {
    return await new Oid4VpHolderBuilder(kms, vault, "client_id").build()
}