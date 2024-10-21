import test from 'ava'
import {Alg, createKeyMetadata, wrapJsKms} from '../index.js'
import jose from 'node-jose'
import {assert} from "./utils.mjs";

test('generate Key Metadata using JS KMS', async t => {
    const key_metadata = await createKeyMetadata(await mockKms())

    const expected_key_metadata = {
        didUrl: 'did:key:zDnaeZWZ4fqhGst7r1X8uguF92M3CxjAjNQwS5eLAPJ1sGCZx#zDnaeZWZ4fqhGst7r1X8uguF92M3CxjAjNQwS5eLAPJ1sGCZx',
        kid: 'test'
    }

    t.like(key_metadata, expected_key_metadata)
})

test('sign and verify', async t => {
    const kms = wrapJsKms(await mockKms())
    const keyHandle = await kms.get('test')

    const payload = new TextEncoder().encode('Secure payload')
    const signature = await keyHandle.sign(payload)
    await keyHandle.verify(payload, signature)

    t.pass()
})

async function mockKms() {
    const jwkWithPrivateKey = {
        "kty": "EC",
        "kid": "618d228e-4767-4aa2-8683-c35c86d7025c",
        "crv": "P-256",
        "x": "huX4QOwcvioB2N3njNOnTOtElUvf7KIQnm6NvdfK2bs",
        "y": "4qWecmcxVAXxyCBYuzxSpVRG7ETk9mO3RjUzsFUtDCg",
        "d": "hp8J4pfRBfqAeEOED4pnaOrztx1nc8X76npPjq6nF_c"
    };

    const keystore = jose.JWK.createKeyStore()
    const key = await keystore.add(jwkWithPrivateKey, 'json')

    const publicKeyBytes = Buffer.from(
        'huX4QOwcvioB2N3njNOnTOtElUvf7KIQnm6NvdfK2bs4qWecmcxVAXxyCBYuzxSpVRG7ETk9mO3RjUzsFUtDCg',
        'base64'
    )
    const publicKey = Array.from(publicKeyBytes);
    const jwk = JSON.stringify(key.toJSON());

    const keyHandle = {
        pubKey: publicKey,
        jwk: jwk,
        alg: Alg.ES256,
        async sign(payload) {
            const payloadBuffer = Buffer.from(payload);
            const signature = await jose.JWS.createSign({format: 'compact', alg: 'ES256'}, key)
                .update(payloadBuffer)
                .final();
            return new Uint8Array(Buffer.from(signature));
        },
        async verify(data, signature) {
            const signatureStr = Buffer.from(signature).toString('utf8')
            const result = await jose.JWS.createVerify(keystore).verify(signatureStr)
            const payload = Buffer.from(result.payload).toString()
            const expected_payload = Buffer.from(data).toString('utf8')
            assert(payload === expected_payload, `Verification failed: Actual: ${payload}, Expected: ${data}`)
        },
    };

    return {
        async create(kt) {
            return 'test'
        },
        async get(kid) {
            return keyHandle
        }
    };
}
