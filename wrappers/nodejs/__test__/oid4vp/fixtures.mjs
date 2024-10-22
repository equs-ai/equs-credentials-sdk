export const AUTH_REQUEST_JWT = 'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVzRVg3OUdGUWY0Y1g5d0t4YldIQkplcHU1akhlNTNXUm5hc2RoV2daOEZLUiN6RG5hZXNFWDc5R0ZRZjRjWDl3S3hiV0hCSmVwdTVqSGU1M1dSbmFzZGhXZ1o4RktSIiwidHlwIjoiSldUIn0.eyJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJub25jZSI6ImF2SzI1cUdsaDBmejg0T3MtR1JabV9NOTFRT09ya0JSaV9TdXNXbmpiZmMiLCJjbGllbnRfbWV0YWRhdGEiOnsidnBfZm9ybWF0cyI6eyJ2YytzZC1qd3QiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTYiXX19fSwiY2xpZW50X2lkIjoiZGlkOmtleTp6RG5hZXNFWDc5R0ZRZjRjWDl3S3hiV0hCSmVwdTVqSGU1M1dSbmFzZGhXZ1o4RktSIiwiY2xpZW50X2lkX3NjaGVtZSI6ImRpZCIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMjRjYzFlNGQtMTRhNy00ZjhjLWIyY2YtMDNmZjQ5YzRjYTk2IiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiSWRlbnRpdHktMSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjdCJdLCJwcmVkaWNhdGUiOm51bGwsImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiY29uc3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwifSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm5hbWUiXSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX1dfSwibmFtZSI6IklkZW50aXR5IFZDIiwicHVycG9zZSI6IldlIHdhbnQgYW4gaWRlbnRpdHkiLCJmb3JtYXQiOnsidmMrc2Qtand0Ijp7InNkLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2IiwiRWREU0EiXSwia2Itand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiLCJFZERTQSJdfX19XSwibmFtZSI6IkV4YW1wbGUgd2l0aCBzZWxlY3RpdmUgZGlzY2xvc3VyZSJ9LCJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjkwMDEvcmVzcG9uc2UifQ.30DJ-SfGbANtnYqUhlcA1ploTAPz-TLMk_E7Amedzsa29N5UPj076lVDdwAi6bOsK0-evgijKL6V1gfSfFYYaA'

export const AUTH_REQUEST = {
    "clientId": "did:key:zDnaesEX79GFQf4cX9wKxbWHBJepu5jHe53WRnasdhWgZ8FKR",
    "presentationDefinition": {
        "id": "24cc1e4d-14a7-4f8c-b2cf-03ff49c4ca96",
        "input_descriptors": [
            {
                "id": "Identity-1",
                "constraints": {
                    "fields": [
                        {
                            "path": [
                                "$.vct"
                            ],
                            "predicate": null,
                            "filter": {
                                "type": "string",
                                "const": "https://credentials.example.com/identity_credential"
                            },
                            "intent_to_retain": false
                        },
                        {
                            "path": [
                                "$.name"
                            ],
                            "intent_to_retain": false,
                            "predicate": null,
                        }
                    ]
                },
                "name": "Identity VC",
                "purpose": "We want an identity",
                "format": {
                    "vc+sd-jwt": {
                        "sd-jwt_alg_values": [
                            "ES256",
                            "EdDSA"
                        ],
                        "kb-jwt_alg_values": [
                            "ES256",
                            "EdDSA"
                        ]
                    }
                }
            }
        ],
        "name": "Example with selective disclosure"
    },
    "responseUri": "http://localhost:9001/response",
    "responseMode": "direct_post",
    "nonce": "avK25qGlh0fz84Os-GRZm_M91QOOrkBRi_SusWnjbfc",
}

export const PRESENTATION_DEFINITION = {
    "id": "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
    "input_descriptors": [
        {
            "id": "Identity-1",
            "name": "Identity VC",
            "purpose": "We want an identity",
            "format": {
                "vc+sd-jwt": {
                    "sd-jwt_alg_values": ["ES256", "EdDSA"],
                    "kb-jwt_alg_values": ["ES256", "EdDSA"]
                }
            },
            "constraints": {
                "fields": [
                    {
                        "path": [
                            "$.vct"
                        ],
                        "filter": {
                            "type": "string",
                            "const": "https://credentials.example.com/identity_credential"
                        }
                    },
                    {
                        "path": [
                            "$.name"
                        ]
                    }
                ]
            }
        }
    ]
}

export const PRESENTATION_SUBMISSION = {
    id: "e18f2155-1235-43e9-8f0c-1f18cf72911a",
    definition_id: "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
    descriptor_map: [{id: "Identity-1", format: "vc+sd-jwt", path: "$"}]
}

export const VC_TYPE = 'https://credentials.example.com/identity_credential'

export const VC = 'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~'
export const VP = 'eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJub25jZSI6Im4wTmNFIiwiYXVkIjoiZGlkOmtleTp6RG5hZWZRQVBGVlF0OXNmVTYzaHlxWWdQemEycERTWFNKclByQ0c1cGFUNWVhUUpiIiwic2RfaGFzaCI6Im45dkFaUU04ZFNZSWVlVnJCLVExSHJGaWppY2VvcXBXUXV4SjFFT1lQSjQiLCJpYXQiOjE3Mjg4ODI2MTF9.2SQRzj4_PDTxVqoWCWtPGGgOzDn2d7sk6e8okhdAzqLgtvF6hUuOqHqzPd2XIJEDPtP0gfeV6W2dMRx3hKdrDA'

export const CLAIMS = {
    'Identity-1': {
        vct: 'https://credentials.example.com/identity_credential',
        sub: 'did:key:zDnaej9QadgdZnu8uDXZXd4545dfJAEvmV6nn7xaYUqzcrPvM',
        nbf: 1728882611,
        iss: 'did:key:zDnaexeh3T1CziWWSEeWpyuTkXqiT5ikiCw5iZQRBv4HXuex6',
        iat: 1728882611,
        exp: 1760418611,
        cnf: {
            jwk: {
                kty: "EC",
                crv: "P-256",
                x: "FhAMv-TXg2gSe8jjfHUqgdO7_26eHomYSpyLqBM9ZSY",
                y: "AMzSmIth0vBQ1ff28FQzsZZI-WrLYuqqHR8L_GlvkYs",
            }
        },
        name: 'John'
    }
}

