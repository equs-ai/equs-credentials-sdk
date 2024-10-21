import test from 'ava';
import {wrapJsNonceGenerator} from "../index.js";

test('generate Nonce', async t => {
    const nonce_generator = wrapJsNonceGenerator(mockNonceGenerator())

    const nonce = await nonce_generator.generate()

    t.is(nonce, 'nOnce')
})

test('generate Nonce with expiration', async t => {
    const nonce_generator = wrapJsNonceGenerator(mockNonceGenerator())

    const nonce = await nonce_generator.withExpiration(3600)

    console.log(nonce)

    t.is(nonce.nonce, 'nOnce')
    t.is(nonce.expiresIn, 3600)
})

function mockNonceGenerator() {
    return {
        async generate() {
            return 'nOnce'
        }
    }
}