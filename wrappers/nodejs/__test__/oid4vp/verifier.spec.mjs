import test from "ava";
import {
    authRequestAsUrlByReference, authRequestAsUrlByValue,
    createKeyMetadata,
    inMemKms,
    localNonceGenerator,
    Oid4VpVerifierBuilder
} from "../../index.js";
import {isEmpty} from "../utils.mjs";
import {CLAIMS, PRESENTATION_DEFINITION, PRESENTATION_SUBMISSION, VP} from "./fixtures.mjs";

test('create Authorization Request', async t => {
    const verifier = await buildVerifier()

    let authorizationRequestWithSession = await verifier.createAuthorizationRequest(PRESENTATION_DEFINITION, 'http://localhost:9001/response')
    let by_reference = authRequestAsUrlByReference(authorizationRequestWithSession.authorizationRequest, 'http://localhost:9001/response')
    let by_value = authRequestAsUrlByValue(authorizationRequestWithSession.authorizationRequest)

    t.false(isEmpty(by_reference))
    t.false(isEmpty(by_value))
    t.false(isEmpty(authorizationRequestWithSession.session.nonce))
    t.like(authorizationRequestWithSession.session.presentationDefinition, PRESENTATION_DEFINITION)
})

test('verify Authorization Response', async t => {
    const verifier = await buildVerifier('did:key:zDnaefQAPFVQt9sfU63hyqYgPza2pDSXSJrPrCG5paT5eaQJb')

    const session = {
        nonce: 'n0NcE',
        presentationDefinition: PRESENTATION_DEFINITION,
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
    let key_metadata = await createKeyMetadata(kms)

    return await new Oid4VpVerifierBuilder(kms, nonce_generator, key_metadata, client_id).build()
}