import {
  Claims,
  CommonAuthorizationRequest,
  CredentialFormats,
  PresentationDefinition,
  PresentationSubmission,
} from "agent-sdk";

export const AUTH_REQUEST_JWT =
  "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVyMWQzSHBkZzZSSDdLUmhXWFJ0enBpakVtOEd0YVZRbjdCdFN3N0RpVzcyRSN6RG5hZXIxZDNIcGRnNlJIN0tSaFdYUnR6cGlqRW04R3RhVlFuN0J0U3c3RGlXNzJFIiwidHlwIjoiYXBwbGljYXRpb24vb2F1dGgtYXV0aHotcmVxK2p3dCJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJzdGF0ZSI6IjFkOGIwZDkzLTg2ZTgtNDEzNS04N2Q0LTUyNGJiMDUwMGJmMyIsInRyYW5zYWN0aW9uX2RhdGEiOlsiZXlKMGVYQmxJam9pYzI5dFpWOTBlWEJsSWl3aVkzSmxaR1Z1ZEdsaGJGOXBaSE1pT2xzaVNXUmxiblJwZEhrdE1TSmRMQ0owY21GdWMyRmpkR2x2Ymw5a1lYUmhYMmhoYzJobGMxOWhiR2NpT2xzaWMyaGhMVEkxTmlJc0luTm9ZUzAxTVRJaVhYMCJdLCJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJub25jZSI6IkVBOXp6VV9rUWZnR1VGMk1pd3JZdUZnTWdQcFhVRnpxc1B4cy16RWRvREkiLCJjbGllbnRfbWV0YWRhdGEiOnsidnBfZm9ybWF0c19zdXBwb3J0ZWQiOnsiZGMrc2Qtand0Ijp7InNkLWp3dF9hbGdfdmFsdWVzIjpbIkVkRFNBIiwiRVMyNTYiXSwia2Itand0X2FsZ192YWx1ZXMiOlsiRWREU0EiLCJFUzI1NiJdfX0sImp3a3MiOnsia2V5cyI6W3sidXNlIjoiZW5jIiwiYWxnIjoiRVMyNTYiLCJraWQiOiIxQ0tUN1NtaG9oOlAyNTY6Iiwia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJZUE5aOEc1ZDRTTzhuR1g1QWZIOEgxeW9nODFBZ181czd5emZkNVN2MUt3IiwieSI6Ijg0T0dGWEdxTUF0cVpBUTlDNkJUN0VWMDJiVUFtNk9IbDVkN1kzMGdPazAifV19LCJlbmNyeXB0ZWRfcmVzcG9uc2VfZW5jX3ZhbHVlc19zdXBwb3J0ZWQiOlsiQTEyOEdDTSIsIkExMjhDQkMtSFMyNTYiXSwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbImRpZDprZXkiXX0sImNsaWVudF9pZCI6ImRlY2VudHJhbGl6ZWRfaWRlbnRpZmllcjpkaWQ6a2V5OnpEbmFlcjFkM0hwZGc2Ukg3S1JoV1hSdHpwaWpFbThHdGFWUW43QnRTdzdEaVc3MkUiLCJwcmVzZW50YXRpb25fZGVmaW5pdGlvbiI6eyJpZCI6ImY2NGVkYzk5LTJiNzktNDVjZS1hZDM2LTVlMzQ2ZWJmYzZlYyIsImlucHV0X2Rlc2NyaXB0b3JzIjpbeyJpZCI6IklkZW50aXR5LTEiLCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC52Y3QiXSwiZmlsdGVyIjp7InR5cGUiOiJzdHJpbmciLCJjb25zdCI6Imh0dHBzOi8vY3JlZGVudGlhbHMuZXhhbXBsZS5jb20vaWRlbnRpdHlfY3JlZGVudGlhbCJ9LCJwcmVkaWNhdGUiOm51bGwsImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC5uYW1lIl0sIm9wdGlvbmFsIjp0cnVlLCJwcmVkaWNhdGUiOm51bGwsImludGVudF90b19yZXRhaW4iOmZhbHNlfV19LCJuYW1lIjoiSWRlbnRpdHkgVkMiLCJwdXJwb3NlIjoiV2Ugd2FudCBhbiBpZGVudGl0eSIsImZvcm1hdCI6eyJkYytzZC1qd3QiOnsic2Qtand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiLCJFZERTQSJdLCJrYi1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiIsIkVkRFNBIl19fX1dLCJuYW1lIjoiRXhhbXBsZSB3aXRoIHNlbGVjdGl2ZSBkaXNjbG9zdXJlIn0sInJlc3BvbnNlX3VyaSI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMS9yZXNwb25zZSJ9.DPsKN_vh20a9rLFeRzLvEFim-TqRGH0G9GAAd9ezV7yWUsZcBjOyVp6nk0pTPTN4uD-jWp2xsKv1fmwU3ke1QA";
export const STATE = "1d8b0d93-86e8-4135-87d4-524bb0500bf3";

export const PRESENTATION_DEFINITION: PresentationDefinition = {
  id: "f64edc99-2b79-45ce-ad36-5e346ebfc6ec",
  input_descriptors: [
    {
      id: "Identity-1",
      constraints: {
        fields: [
          {
            path: ["$.vct"],
            filter: {
              type: "string",
              const: "https://credentials.example.com/identity_credential",
            },
            predicate: null,
            intent_to_retain: false,
          },
          {
            path: ["$.name"],
            optional: true,
            predicate: null,
            intent_to_retain: false,
          },
        ],
      },
      name: "Identity VC",
      purpose: "We want an identity",
      format: {
        "dc+sd-jwt": {
          "sd-jwt_alg_values": ["ES256", "EdDSA"],
          "kb-jwt_alg_values": ["ES256", "EdDSA"],
        },
      },
    },
  ],
  name: "Example with selective disclosure",
};
export const PRESENTATION_DEFINITION_FAKE: PresentationDefinition = {
  id: "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
  input_descriptors: [
    {
      id: "Identity-1",
      name: "Identity VC",
      purpose: "We want an identity",
      format: {
        "dc+sd-jwt": {
          "sd-jwt_alg_values": ["ES256", "EdDSA"],
          "kb-jwt_alg_values": ["ES256", "EdDSA"],
        },
      },
      constraints: {
        fields: [
          {
            path: ["$.vct"],
            predicate: null,
            filter: {
              type: "string",
              const: "https://credentials.example.com/identity_credential_1",
            },
            intent_to_retain: false,
          },
          {
            path: ["$.name"],
            intent_to_retain: false,
            predicate: null,
            optional: true,
          },
        ],
      },
    },
  ],
};

export const AUTH_REQUEST: CommonAuthorizationRequest = {
  client_id: "decentralized_identifier:did:key:zDnaer1d3Hpdg6RH7KRhWXRtzpijEm8GtaVQn7BtSw7DiW72E",
  client_metadata: {
    vp_formats_supported: {
      "dc+sd-jwt": {
        "sd-jwt_alg_values": ["EdDSA", "ES256"],
        "kb-jwt_alg_values": ["EdDSA", "ES256"],
      },
    },
    jwks: {
      keys: [
        {
          use: "enc",
          alg: "ES256",
          kid: "1CKT7Smhoh:P256:",
          kty: "EC",
          crv: "P-256",
          x: "YPNZ8G5d4SO8nGX5AfH8H1yog81Ag_5s7yzfd5Sv1Kw",
          y: "84OGFXGqMAtqZAQ9C6BT7EV02bUAm6OHl5d7Y30gOk0",
        },
      ],
    },
    encrypted_response_enc_values_supported: ["A128GCM", "A128CBC-HS256"],
    subject_syntax_types_supported: ["did:key"],
  },
  response_uri: "http://localhost:9001/response",
  response_mode: "direct_post",
  response_type: "vp_token",
  nonce: "EA9zzU_kQfgGUF2MiwrYuFgMgPpXUFzqsPxs-zEdoDI",
  state: STATE,
  presentation_definition: PRESENTATION_DEFINITION,
  transaction_data: [
    {
      type: "some_type",
      credential_ids: ["Identity-1"],
      transaction_data_hashes_alg: ["sha-256", "sha-512"],
    },
  ],
};

export const AUTH_REQUEST_WITH_DIRECT_POST_JWT: CommonAuthorizationRequest = {
  ...AUTH_REQUEST,
  client_metadata: {
    ...AUTH_REQUEST.client_metadata,
    jwks: {
      keys: [
        {
          kid: "ecdsa-kid",
          kty: "EC",
          crv: "P-256",
          x: "SSnPfyVhQgcU9Aaynqgi6QGhrq7K7WFEC0mAvpHG4TM",
          y: "rYQ5mLQLTs95WLBKKA8R5IjMTXjX13iZnzazsVectRY",
          alg: "ES256",
        },
      ],
    },
  },
  response_mode: "direct_post.jwt",
};

export const AUTH_REQUEST_FAKE: CommonAuthorizationRequest = {
  ...AUTH_REQUEST,
  presentation_definition: PRESENTATION_DEFINITION_FAKE,
};

export const PRESENTATION_SUBMISSION: PresentationSubmission = {
  id: "e18f2155-1235-43e9-8f0c-1f18cf72911a",
  definition_id: "f64edc99-2b79-45ce-ad36-5e346ebfc6ec",
  descriptor_map: [{ id: "Identity-1", format: CredentialFormats.VCSDJWT, path: "$", path_nested: null }],
};

export const VC_TYPE = "https://credentials.example.com/identity_credential";

export const VC =
  "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~";
export const VC_WITH_STATUS =
  "eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVmYUdTd1RmWmsyVXVRV1JqRFQ1Z3J0TEw2RWE1Z3hGcjVBN1hyMzZIUXdtQiN6RG5hZWZhR1N3VGZaazJVdVFXUmpEVDVncnRMTDZFYTVneEZyNUE3WHIzNkhRd21CIn0.eyJfc2QiOlsiTGtNQ3hnT3dKZXVWa2xFUVIxYUl1TDVUSXllRkZiSUhEYXNjZk9EOGlHWSIsInc5WHpEVG5YMFRNOVFFX0NjYUVSaUtpbVV3VkFkWEwxRzZIdU1wZHdkclkiXSwiYWRkcmVzcyI6IjIyMUIgQmFrZXIgU3RyZWV0IiwiaWF0IjoxNzUzMDU0NDQ4LCJkYXRlIjoiMDkvMDkvMTk4OSIsInN1YiI6ImRpZDprZXk6ekRuYWVoVzJXWERnaHBNMTZYRzN5Z2Vja2FSTWJpamJjWG9tZnQ0ZzI2cnlpUlZXUiIsInZjdCI6Imh0dHBzOi8vY3JlZGVudGlhbHMuZXhhbXBsZS5jb20vaWRlbnRpdHlfY3JlZGVudGlhbCIsInN0YXR1cyI6eyJzdGF0dXNfbGlzdCI6eyJ1cmkiOiJodHRwOi8vbG9jYWxob3N0OjkwMDEvc3RhdHVzX2xpc3QiLCJpZHgiOjF9fSwiX3NkX2FsZyI6InNoYS0yNTYiLCJpc3MiOiJkaWQ6a2V5OnpEbmFlZmFHU3dUZlprMlV1UVdSakRUNWdydExMNkVhNWd4RnI1QTdYcjM2SFF3bUIiLCJleHAiOjE3NTMwNTUwNDgsIm5iZiI6MTc1MzA1NDQ0OCwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6Il9hRHExTWE2SFNOUUZrR0F0ZnBpNlR3UnVuMUhlVnpCWWo2R29DcEhmcW8iLCJ5IjoiSTY0VnRmaTNlbzktQTM0TmNNMFJ4cHRsbzhiOGd1RUV3dnd2S2w1YUZlWSJ9fX0.jruSbbpygwgyWcJ2DO0myKlGimKW0n_dsYc5l-hksJqIWZF2Wy5Sf01nZlkUop-_JkN3x9Ct1kCOHes8-Ozdxg~WyJ1eExOVGVtV1FrYzFWTzZMZ3NBcmxRIiwgIm5hbWUiLCAiSm9obiJd~WyIyQ0J1ZENXSTVFSW1haGd6ZGNVMVZ3IiwgInN1cm5hbWUiLCAiRG9lIl0~";
export const VP =
  "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJub25jZSI6Im4wTmNFIiwiYXVkIjoiZGlkOmtleTp6RG5hZWZRQVBGVlF0OXNmVTYzaHlxWWdQemEycERTWFNKclByQ0c1cGFUNWVhUUpiIiwic2RfaGFzaCI6Im45dkFaUU04ZFNZSWVlVnJCLVExSHJGaWppY2VvcXBXUXV4SjFFT1lQSjQiLCJpYXQiOjE3Mjg4ODI2MTF9.2SQRzj4_PDTxVqoWCWtPGGgOzDn2d7sk6e8okhdAzqLgtvF6hUuOqHqzPd2XIJEDPtP0gfeV6W2dMRx3hKdrDA";

export const CLAIMS: Claims = {
  vp_token: {
    "Identity-1": {
      vct: "https://credentials.example.com/identity_credential",
      sub: "did:key:zDnaej9QadgdZnu8uDXZXd4545dfJAEvmV6nn7xaYUqzcrPvM",
      nbf: 1728882611,
      iss: "did:key:zDnaexeh3T1CziWWSEeWpyuTkXqiT5ikiCw5iZQRBv4HXuex6",
      iat: 1728882611,
      exp: 1760418611,
      cnf: {
        jwk: {
          kty: "EC",
          crv: "P-256",
          x: "FhAMv-TXg2gSe8jjfHUqgdO7_26eHomYSpyLqBM9ZSY",
          y: "AMzSmIth0vBQ1ff28FQzsZZI-WrLYuqqHR8L_GlvkYs",
        },
      },
      name: "John",
    },
  },
};
