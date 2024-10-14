export const AUTH_REQUEST_JWT = 'eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVhZ3ZXMmVEV2MyeVZ3N0I5OG92Y0o4amRkbjdUOU1oM3k1VmlreXM2eTRrWCN6RG5hZWFndlcyZURXYzJ5Vnc3Qjk4b3ZjSjhqZGRuN1Q5TWgzeTVWaWt5czZ5NGtYIiwidHlwIjoiSldUIn0.eyJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV91cmkiOiJodHRwOi8vMTI3LjAuMC4xOjU1Nzk2L2F1dGgiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJub25jZSI6Im4wTmNFIiwiY2xpZW50X21ldGFkYXRhIjp7InZwX2Zvcm1hdHMiOnsidmMrc2Qtand0Ijp7ImFsZyI6WyJFZERTQSIsIkVTMjU2Il19fX0sInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMWI5ZDZiY2QtYmJmZC00YjJkLTliNWQtYWI4ZGZiYmQ0YmVkIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiSWRlbnRpdHktMSIsIm5hbWUiOiJJZGVudGl0eSBWQyIsInB1cnBvc2UiOiJXZSB3YW50IGFuIGlkZW50aXR5IiwiZm9ybWF0Ijp7InZjK3NkLWp3dCI6eyJhbGciOlsiRWREU0EiLCJFUzI1NksiXX19LCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC52Y3QiXSwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJjb25zdCI6Imh0dHBzOi8vY3JlZGVudGlhbHMuZXhhbXBsZS5jb20vaWRlbnRpdHlfY3JlZGVudGlhbCJ9fSx7InBhdGgiOlsiJC5uYW1lIl19XX19XX0sImNsaWVudF9pZCI6ImRpZDprZXk6ekRuYWVhZ3ZXMmVEV2MyeVZ3N0I5OG92Y0o4amRkbjdUOU1oM3k1VmlreXM2eTRrWCIsImNsaWVudF9pZF9zY2hlbWUiOiJkaWQifQ.RlrD5ibioAvM_S0QAhdPK--9WyLEw258cMduAn26S1puXIxKgJod9gt00FDrK0x-jdPmkuPdpJWKzg3kcimIVQ'

export const AUTH_REQUEST = {
    "clientId": "did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX",
    "presentationDefinition": {
        "id": "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
        "input_descriptors": [
            {
                "id": "Identity-1",
                "name": "Identity VC",
                "purpose": "We want an identity",
                "format": {
                    "vc+sd-jwt": {
                        "alg": [
                            "EdDSA",
                            "ES256K"
                        ]
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
    },
    "nonce": "n0NcE",
    "responseMode": "direct_post",
    "responseUri": "http://localhost:9001/response"
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
                    "alg": [
                        "EdDSA",
                        "ES256K"
                    ]
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
    id: "e18f2155-1235-43e9-8f0c-1f18cf72911a,definition_id:1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
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

