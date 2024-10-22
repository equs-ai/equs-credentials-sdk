import test from "ava";
import {
    createDidAndKeyMetadata,
    inMemKms,
    localNonceGenerator,
    Oid4VpVerifierBuilder,
    PassAuthRequestObject
} from "../../index.js";
import {isEmpty} from "../utils.mjs";
import {CLAIMS, PRESENTATION_DEFINITION, PRESENTATION_SUBMISSION, VP} from "./fixtures.mjs";

test('create Authorization Request', async t => {
    const verifier = await buildVerifier()

    let authResponseOptions = {
        mode: "direct_post",
        type: "vp_token",
        submissionUri: "http://localhost:9001/response",
    }

    let authReqByValue = await verifier.createAuthorizationRequest(
        PRESENTATION_DEFINITION,
        authResponseOptions,
        PassAuthRequestObject.byValue(),
        null
    );


    t.true(authReqByValue.authorizationRequestUri.includes('request=eyJh'))
    t.false(isEmpty(authReqByValue.session.nonce))
    t.like(authReqByValue.session.presentationDefinition, PRESENTATION_DEFINITION)

    let authReqByReference = await verifier.createAuthorizationRequest(
        PRESENTATION_DEFINITION,
        authResponseOptions,
        PassAuthRequestObject.byReference('http://localhost:9001/request'),
        null
    );

    t.true(authReqByReference.authorizationRequestUri.includes('request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest'))
    t.false(isEmpty(authReqByReference.session.nonce))
    t.like(authReqByReference.session.presentationDefinition, PRESENTATION_DEFINITION)
})

test('verify Authorization Response', async t => {
    const verifier = await buildVerifier('did:key:zDnaefQAPFVQt9sfU63hyqYgPza2pDSXSJrPrCG5paT5eaQJb')

    const session = {
        nonce: 'n0NcE',
        presentationDefinition: PRESENTATION_DEFINITION,
        authorizationRequestJwt: "",

    }

    const auth_request = {
        vpToken: VP,
        presentationSubmission: PRESENTATION_SUBMISSION
    }

    const claims = await verifier.verifyPresentation(auth_request, session)

    t.like(claims, CLAIMS)
})

async function buildVerifier(client_id = 'did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX') {
    let kms = inMemKms()
    let nonce_generator = localNonceGenerator()
    let {keyMetadata} = await createDidAndKeyMetadata(kms)

    return await new Oid4VpVerifierBuilder(kms, nonce_generator, keyMetadata, client_id).build()
}