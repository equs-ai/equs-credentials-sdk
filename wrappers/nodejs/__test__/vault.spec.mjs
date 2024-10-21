import test from 'ava';
import {Alg, CredentialSearchCriteria, wrapJsVault, VCFormat} from "../index.js";
import {assert} from "./utils.mjs";

const CREDENTIAL_DATA = {
    id: 'test',
    credential: {
        format: VCFormat.SdJwtVc,
        payload: 'eyJ0eXAiOiJzZCtqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpZCI6IjEyMzQiLCJfc2QiOlsiYkRUUnZtNS1Zbi1IRzdjcXBWUjVPVlJJ' +
            'WHNTYUJrNTdKZ2lPcV9qMVZJNCIsImV0M1VmUnlsd1ZyZlhkUEt6Zzc5aGNqRDFJdHpvUTlvQm9YUkd0TW9zRmsiLCJ6V2ZaTlMxOUF0Yl' +
            'JTVGJvN3NKUm4wQlpRdldSZGNob0M3VVphYkZyalk4Il0sIl9zZF9hbGciOiJzaGEtMjU2In0.n27NCtnuwytlBYtUNjgkesDP_7gN7bha' +
            'LhWNL4SWT6MaHsOjZ2ZMp987GgQRL6ZkLbJ7Cd3hlePHS84GBXPuvg~WyI1ZWI4Yzg2MjM0MDJjZjJlIiwiZmlyc3RuYW1lIiwiSm9obiJ' +
            'd~WyJjNWMzMWY2ZWYzNTg4MWJjIiwibGFzdG5hbWUiLCJEb2UiXQ~WyJmYTlkYTUzZWJjOTk3OThlIiwic3NuIiwiMTIzLTQ1LTY3ODkiX' +
            'Q~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3MTAwNjk3MjIsImF1ZCI6ImRpZDpleGFtcGxlOjEyMyIsIm5vbmN' +
            'lIjoiazh2ZGYwbmQ2Iiwic2RfaGFzaCI6Il8tTmJWSzNmczl3VzNHaDNOUktSNEt1NmZDMUwzN0R2MFFfalBXd0ppRkUifQ.pqw2OB5IA5' +
            'ya9Mxf60hE3nr2gsJEIoIlnuCa4qIisijHbwg3WzTDFmW2SuNvK_ORN0WU6RoGbJx5uYZh8k4EbA'
    },
    metadata: {
        type: 'personal',
        format: VCFormat.SdJwtVc,
        kid: 'kid',
        alg: Alg.ES256,
        tags: [{key: 'firstname', value: 'John'}],
    }
}

test('store Credential', async t => {
    const data = CREDENTIAL_DATA
    const vault = await wrapJsVault(mockVault(data))

    await vault.storeCredential(data.credential, data.metadata)

    t.pass()
})

test('get Credential', async t => {
    const data = CREDENTIAL_DATA
    const vault = await wrapJsVault(mockVault(data))

    const entry = await vault.getCredential(data.id)

    t.like(entry, {credential: data.credential, kid: data.metadata.kid})
})

test('find Credentials', async t => {
    const data = CREDENTIAL_DATA
    const vault = await wrapJsVault(mockVault(data))

    await vault.findCredentials(CredentialSearchCriteria.byTypeAndFormat(data.metadata.type, 'vc+sd-jwt'))

    t.pass()
})

function mockVault(credential_data) {
    return {
        async storeCredential(credential, metadata) {
            assert(
                credential.format === credential_data.credential.format
                && credential.payload === credential_data.credential.payload,
                `Invalid credential: ${JSON.stringify(credential)}`
            )
            assert(
                metadata.type === credential_data.metadata.type
                && metadata.format === credential_data.metadata.format
                && metadata.kid === credential_data.metadata.kid
                && metadata.alg === credential_data.metadata.alg,
                `Invalid metadata: ${JSON.stringify(metadata)}`
            )
            return credential_data.id
        },
        async getCredential(id) {
            assert(
                id === credential_data.id,
                `Invalid ID: ${id}`
            )
            return {
                credential: credential_data.credential,
                kid: credential_data.metadata.kid,
            }
        },
        async findCredentials(criteria) {
            assert(
                criteria.value().type === 'ByTypeAndFormat'
                && criteria.value().cred_type === credential_data.metadata.type
                && criteria.value().format === 'vc+sd-jwt',
                `Invalid criteria: ${JSON.stringify(criteria)}`
            )
            return [{
                credential: credential_data.credential,
                kid: credential_data.metadata.kid,
            }]
        },
    }
}