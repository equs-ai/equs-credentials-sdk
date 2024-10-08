import test from 'ava'

import {inMemKms, inMemVault, IssuerBuilder, IssuerDiscovery, HolderBuilder, localNonceGenerator} from "../index.js";

test('build Issuer', async _ => {
    let kms = inMemKms()
    let vault = inMemVault()
    let nonce_generator = localNonceGenerator()

    let issuer_metadata = {
        "credential_issuer": "https://issuer-backend.com",
        "authorization_servers": ["https://auth-backend.com"],
        "credential_endpoint": "https://issuer-backend.com/credential",
        "credential_configurations_supported": {
            "CRED_DEF_ID": {
                "format": "vc+sd-jwt",
                "scope": "SD_JWT_cred",
                "cryptographic_binding_methods_supported": [
                    "jwk"
                ],
                "credential_signing_alg_values_supported": [
                    "ES256"
                ],
                "proof_types_supported": {
                    "jwt": {
                        "proof_signing_alg_values_supported": [
                            "ES256"
                        ],
                    },
                },
                "vct": "SD_JWT_cred",
                "credential_definition": {
                    "type": "SD_JWT_cred",
                    "claims": {
                        "given_name": {},
                        "family_name": {},
                        "dob": {},
                    },
                },
            },
        },
    }


    let cred_offer = {
        "credential_issuer": "http://localhost.com:8088",
        "credential_configuration_ids": [
            "CRED_DEF_ID"
        ],
        "grants": {
            "authorization_code": {
                "issuer_state": null
            }
        }
    }

    let key_metadata = {
        didUrl: "",
        kid: "",
    }

    console.log(JSON.stringify(cred_offer))


    let issuer = await new IssuerBuilder(kms, nonce_generator, JSON.stringify(issuer_metadata), key_metadata).build()
    let retrieved_issuer_metadata = issuer.getIssuerMetadata();
    console.log(retrieved_issuer_metadata)

    let holder = await new HolderBuilder(kms, vault, "client_id", IssuerDiscovery.fromOffer(JSON.stringify(cred_offer))).build()
    let some_data = await holder.authzCodeFlowWithScope("test", (url) => url)
    console.log(some_data)

})