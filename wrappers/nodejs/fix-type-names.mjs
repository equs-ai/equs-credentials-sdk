// TODO: Remove this script after the following bugs have been fixed: https://github.com/napi-rs/napi-rs/issues/1586, https://github.com/napi-rs/napi-rs/issues/1666
import fs from 'fs/promises';

// JS types that are not renamed automatically should be added to this list.
const replacements = [
    {from: 'JsAlg', to: 'Alg'},
    {from: 'JsKeyType', to: 'KeyType'},
    {from: 'JsCredential', to: 'Credential'},
    {from: 'JsCredentialMetadata', to: 'CredentialMetadata'},
    {from: 'JsCredentialEntry', to: 'CredentialEntry'},
    {from: 'JsAuthorizationResponse', to: 'AuthorizationResponse'},
    {from: 'JsPresentationSession', to: 'PresentationSession'},
    {from: 'JsKeyMetadata', to: 'KeyMetadata'},
    {from: 'JsDIDAndKeyMetadata', to: 'DIDAndKeyMetadata'},
    {from: 'JsonObject', to: 'Record<string, any>'},
];

(async () => {
    try {
        let content = await fs.readFile('index.d.ts', 'utf8');

        for (const replacement of replacements) {
            content = content.split(replacement.from).join(replacement.to);
            console.log(`Rename "${replacement.from}" to "${replacement.to}" in index.d.ts file`);
        }

        await fs.writeFile('index.d.ts', content, 'utf8');
    } catch (error) {
        console.error('Error occurred:', error);
    }
})();
