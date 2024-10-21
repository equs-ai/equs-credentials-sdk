import test from 'ava'

import {
    createKeyMetadata,
    CredentialSearchCriteria,
    inMemKms,
    inMemVault,
    IssuerDiscovery,
    Oid4VciHolderBuilder,
    VCFormat,
} from "../../index.js";
import {
    ACCESS_TOKEN,
    ACCESS_TOKEN_RESPONSE,
    AUTH_SERVER_METADATA, CODE_RESPONSE, CRED_DEF_ID,
    CRED_OFFER, CRED_RESPONSE, CRED_TYPE,
    ISSUER_METADATA,
    SCOPE, SD_JWT_CREDS,
} from "./fixtures.mjs";
import mockttp from 'mockttp'

const mockServer = mockttp.getLocal()

test.beforeEach(async _ => {
    await mockServer.start(9000)
    await mockServer.forGet('/.well-known/openid-credential-issuer').thenJson(200, ISSUER_METADATA)
    await mockServer.forGet('/auth/.well-known/openid-configuration').thenJson(200, AUTH_SERVER_METADATA)
});

test.afterEach(_ => mockServer.stop());

test.serial('retrieve Issuer Metadata', async t => {
    const vciHolder = await buildHolder()

    const issuerMetadata = vciHolder.getIssuerMetadata()

    t.like(issuerMetadata, ISSUER_METADATA)
})

test.serial('authorize using auth code', async t => {
    await mockServer.forPost('/auth/par/request').thenJson(201, CODE_RESPONSE)
    await mockServer.forPost('/auth/token').thenJson(200, ACCESS_TOKEN_RESPONSE)

    const vciHolder = await buildHolder()

    const token_response =
        await vciHolder.authzCodeFlowWithScope(SCOPE, async (_) => 'code')

    t.like(token_response, ACCESS_TOKEN_RESPONSE)
})

test.serial('request Credential', async t => {
    await mockServer.forPost('/credential').thenJson(200, CRED_RESPONSE)

    const kms = inMemKms();
    const vciHolder = await buildHolder(kms)
    const nonce = {
        nonce: 'KB50VOm9I-kPLT9mAACV8g',
        expiresIn: 86400,
        created: 1728732136,
    }
    const key_metadata = await createKeyMetadata(kms);

    const cred_response = await vciHolder.requestCredential(ACCESS_TOKEN, CRED_DEF_ID, nonce, key_metadata)

    t.like(cred_response, {
        data: {
            credential: {
                format: VCFormat.SdJwtVc,
                payload: SD_JWT_CREDS,
            },
            notificationId: '1111',
        },
        nonceData: {
            nonce: '0GtZieAoAL_3Zafyn6TgCA',
            expiresIn: 86440,
        },
    })
})

test.serial('store Credential', async t => {
    const vault = inMemVault()
    const vciHolder = await buildHolder(inMemKms(), vault)
    const credential = {
        format: VCFormat.SdJwtVc,
        payload: SD_JWT_CREDS,
    }
    const metadata = {
        type: CRED_TYPE,
        kid: "1234",
        format: VCFormat.SdJwtVc,
        tags: [],
    }

    await vciHolder.storeCredential(credential, metadata)

    const criteria = CredentialSearchCriteria.byTypeAndFormat(CRED_TYPE, 'vc+sd-jwt')
    const credentialEntries = await vault.findCredentials(criteria)

    t.like(credentialEntries, [{credential, kid: "1234"}])

    t.pass()
})

async function buildHolder(kms = inMemKms(), vault = inMemVault()) {
    return await new Oid4VciHolderBuilder(kms, vault, "client_id", IssuerDiscovery.fromOffer(CRED_OFFER)).build()
}