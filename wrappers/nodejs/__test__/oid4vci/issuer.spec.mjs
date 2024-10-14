import test from 'ava'
import {Oid4VciIssuerBuilder, inMemKms, localNonceGenerator, createKeyMetadata} from "../../index.js"
import {
    ACCESS_TOKEN, CLAIMS,
    CRED_DEF_ID, CRED_DEF_METADATA, CRED_OFFER,
    CRED_REQUEST, GRANTS,
    ISSUER_METADATA,
} from "./fixtures.mjs"
import {isEmpty} from "../utils.mjs";

test('retrieve Metadata', async t => {
    const issuer = await buildIssuer()
    const issuerMetadata = issuer.getIssuerMetadata();

    t.like(issuerMetadata, ISSUER_METADATA)
})

test('retrieve Credential Definition Metadata', async t => {
    const issuer = await buildIssuer()
    const credDefMetadata = issuer.getCredDefMetadata(CRED_REQUEST);

    t.like(credDefMetadata, CRED_DEF_METADATA)
})

test('create Credential Offer', async t => {
    const issuer = await buildIssuer()
    const credentialOffer = issuer.createCredentialOffer([CRED_DEF_ID], GRANTS);

    t.like(credentialOffer, {
        params: CRED_OFFER,
        url: "openid-credential-offer://?credential_offer={%22credential_issuer%22:%22http://localhost:9000%22,%22credential_configuration_ids%22:[%22IDENTITY_SD_JWT%22],%22grants%22:{%22authorization_code%22:{%22issuer_state%22:null}}}",
    })
})

test('issue Credential', async t => {
    const issuer = await buildIssuer()

    const session = {
        nonce: {
            nonce: 'KB50VOm9I-kPLT9mAACV8g',
            expiresIn: 864484848,
            created: 1728843957,
        }
    }

    const result = await issuer.issueCredential(CRED_REQUEST, ACCESS_TOKEN, CLAIMS, session);

    console.log(JSON.stringify(result))

    t.false(isEmpty(result.value.credential))
})

async function buildIssuer() {
    const kms = inMemKms()
    const nonce_generator = localNonceGenerator()
    const key_metadata = await createKeyMetadata(kms)

    return await new Oid4VciIssuerBuilder(kms, nonce_generator, ISSUER_METADATA, key_metadata).build()
}