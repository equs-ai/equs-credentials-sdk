import {
  Claims,
  CommonAuthorizationRequest,
  CredentialFormats,
  PresentationDefinition,
  PresentationSubmission,
} from "agent-sdk";

export const AUTH_REQUEST_JWT =
  "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVlVEc4OHdwUGhNenVEUnZMUlRUeU5NeUppcDVlNlRMbXNqeXZQaVNZVUZrNyN6RG5hZWVURzg4d3BQaE16dURSdkxSVFR5Tk15SmlwNWU2VExtc2p5dlBpU1lVRms3IiwidHlwIjoiYXBwbGljYXRpb24vb2F1dGgtYXV0aHotcmVxK2p3dCJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJzdGF0ZSI6ImVlYTdiNDhlLTE4NjYtNDFiNC1iZWFlLTAzYjk1ZDQxNjcwYyIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsIm5vbmNlIjoiWXp0QU5nbFJkbVA0Q2h4c3JjUzhVY0dZb1BXd2tnaVVJbWtCclFtZ1drVSIsImNsaWVudF9tZXRhZGF0YSI6eyJ2cF9mb3JtYXRzIjp7ImRjK3NkLWp3dCI6eyJhbGciOlsiRWREU0EiLCJFUzI1NiJdfX19LCJjbGllbnRfaWQiOiJkaWQ6a2V5OnpEbmFlZVRHODh3cFBoTXp1RFJ2TFJUVHlOTXlKaXA1ZTZUTG1zanl2UGlTWVVGazciLCJjbGllbnRfaWRfc2NoZW1lIjoiZGlkIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiIxYjlkNmJjZC1iYmZkLTRiMmQtOWI1ZC1hYjhkZmJiZDRiZWQiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJJZGVudGl0eS0xIiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQudmN0Il0sImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiY29uc3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwifSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubmFtZSJdLCJvcHRpb25hbCI6dHJ1ZSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX1dfSwibmFtZSI6IklkZW50aXR5IFZDIiwicHVycG9zZSI6IldlIHdhbnQgYW4gaWRlbnRpdHkiLCJmb3JtYXQiOnsiZGMrc2Qtand0Ijp7InNkLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2IiwiRWREU0EiXSwia2Itand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiLCJFZERTQSJdfX19XX0sInJlc3BvbnNlX3VyaSI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMS9yZXNwb25zZSJ9.dV0RXxaAJTjnAqGNuPUzMor93gsEkXpoqVRj9-J638lV7mkka4ixXZJ3VIQ0Iqhb7GvCIr0D-7_bWp_xnIYAVA";
export const AUTH_REQUEST_JWT_WITH_TRANSACTION_DATA =
  "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVYSGd3b1dpUkpNNkxWVlNndTdrTkpLc1MzTDRyc1ZoVEJQUlNTajllZzVWWiN6RG5hZVhIZ3dvV2lSSk02TFZWU2d1N2tOSktzUzNMNHJzVmhUQlBSU1NqOWVnNVZaIiwidHlwIjoiYXBwbGljYXRpb24vb2F1dGgtYXV0aHotcmVxK2p3dCJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4gaWRfdG9rZW4iLCJzY29wZSI6Im9wZW5pZCIsImlkX3Rva2VuX3R5cGUiOiJzdWJqZWN0X3NpZ25lZF9pZF90b2tlbiIsInRyYW5zYWN0aW9uX2RhdGEiOlsiZXlKMGVYQmxJam9pZEhsd1pURWlMQ0pqY21Wa1pXNTBhV0ZzWDJsa2N5STZXeUpKWkdWdWRHbDBlUzB4SWwwc0luUnlZVzV6WVdOMGFXOXVYMlJoZEdGZmFHRnphR1Z6WDJGc1p5STZXeUp6YUdFdE1qVTJJbDE5Il0sInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdC5qd3QiLCJub25jZSI6IkNOZXhCWnFQcGxmRF9QV2pnWTZFT2ZpWGpJLWF1TWNCODA5SVZBUVpSUjQiLCJjbGllbnRfbWV0YWRhdGEiOnsidnBfZm9ybWF0cyI6eyJkYytzZC1qd3QiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTYiXX0sImxkcF92YyI6eyJwcm9vZl90eXBlIjpbIkVkMjU1MTlTaWduYXR1cmUyMDE4IiwiRWNkc2FTZWNwMjU2azFTaWduYXR1cmUyMDE5Il19fSwic3ViamVjdF9zeW50YXhfdHlwZXNfc3VwcG9ydGVkIjpbImRpZDprZXkiXSwiandrcyI6eyJrZXlzIjpbeyJ1c2UiOiJlbmMiLCJhbGciOiJFUzI1NiIsImtpZCI6ImtEQlhjOU5Ubnk6UDI1NjoiLCJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6ImVvWDdheXliZkZtSldpcjNoNzJYVi1LVy1BRk9oY3gyUjlfUVA2UjBCZEkiLCJ5IjoiSUtDSUo3MGoyQjEzNGU4aEZYM0ZhMGQxeWllQTNXMmZHck9JNmlpbHpFbyJ9XX0sImVuY3J5cHRlZF9yZXNwb25zZV9lbmNfdmFsdWVzX3N1cHBvcnRlZCI6WyJBMjU2R0NNIl0sImF1dGhvcml6YXRpb25fZW5jcnlwdGVkX3Jlc3BvbnNlX2FsZyI6IkVDREgtRVMiLCJhdXRob3JpemF0aW9uX2VuY3J5cHRlZF9yZXNwb25zZV9lbmMiOiJBMjU2R0NNIn0sImNsaWVudF9pZCI6ImRpZDprZXk6ekRuYWVYSGd3b1dpUkpNNkxWVlNndTdrTkpLc1MzTDRyc1ZoVEJQUlNTajllZzVWWiIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiZjY0ZWRjOTktMmI3OS00NWNlLWFkMzYtNWUzNDZlYmZjNmVjIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiSWRlbnRpdHktMSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjdCJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImNvbnN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsXzEifSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQuZW1haWwud29yayJdLCJwcmVkaWNhdGUiOm51bGwsImludGVudF90b19yZXRhaW4iOmZhbHNlfSx7InBhdGgiOlsiJC51c2VybmFtZSJdLCJvcHRpb25hbCI6dHJ1ZSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQuY291bnRyeSJdLCJmaWx0ZXIiOnsidHlwZSI6InN0cmluZyIsImNvbnN0IjoiVVMifSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQuYWdlX292ZXJfMTgiXSwiZmlsdGVyIjp7InR5cGUiOiJib29sZWFuIiwiY29uc3QiOnRydWV9LCJwcmVkaWNhdGUiOm51bGwsImludGVudF90b19yZXRhaW4iOmZhbHNlfV19LCJuYW1lIjoiSWRlbnRpdHkgVkMiLCJwdXJwb3NlIjoiV2Ugd2FudCBhbiBpZGVudGl0eSIsImZvcm1hdCI6eyJkYytzZC1qd3QiOnsic2Qtand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiLCJFZERTQSJdLCJrYi1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiIsIkVkRFNBIl19fX0seyJpZCI6InJlc2lkZW50LWNhcmQiLCJjb25zdHJhaW50cyI6eyJmaWVsZHMiOlt7InBhdGgiOlsiJC50eXBlIl0sImZpbHRlciI6eyJ0eXBlIjoiYXJyYXkiLCJjb250YWlucyI6eyJjb25zdCI6IlBlcm1hbmVudFJlc2lkZW50Q2FyZCJ9fSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX1dfSwibmFtZSI6IklkZW50aXR5IFZDIiwicHVycG9zZSI6IldlIHdhbnQgYSByZXNpZGVudCBjYXJkIiwiZm9ybWF0Ijp7ImxkcF92YyI6eyJwcm9vZl90eXBlIjpbIkVkMjU1MTlTaWduYXR1cmUyMDE4IiwiRWNkc2FTZWNwMjU2azFTaWduYXR1cmUyMDE5Il19fX0seyJpZCI6ImFsdW1uaS1jYXJkIiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQudHlwZSJdLCJmaWx0ZXIiOnsidHlwZSI6ImFycmF5IiwiY29udGFpbnMiOnsiY29uc3QiOiJBbHVtbmlDcmVkZW50aWFsIn19LCJwcmVkaWNhdGUiOm51bGwsImludGVudF90b19yZXRhaW4iOmZhbHNlfV19LCJuYW1lIjoiVW5pdmVyc2l0eSBWQyIsInB1cnBvc2UiOiJXZSB3YW50IGEgZGlwbG9tYSIsImZvcm1hdCI6eyJsZHBfdmMiOnsicHJvb2ZfdHlwZSI6WyJFY2RzYVJkZmMyMDE5IiwiRWREc2FSZGZjMjAyMiJdfX19XSwibmFtZSI6IkV4YW1wbGUgd2l0aCBzZWxlY3RpdmUgZGlzY2xvc3VyZSJ9LCJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjgwOTgvcHJlc2VudCJ9.Zce8XVbP9Zf1tYIXupYDHiL50a7udE0U734Nwu4iTCjZL-Wz5ZMWIj6jIJS4plfDC2VlsoiIpa1hMHzWWKNU9A";
export const STATE = "eea7b48e-1866-41b4-beae-03b95d41670c";
export const CLIENT_ID_AS_URL_SAFE = "did%3Akey%3AzDnaeXHgwoWiRJM6LVVSgu7kNJKsS3L4rsVhTBPRSSj9eg5VZ";

export const PRESENTATION_DEFINITION: PresentationDefinition = {
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
              const: "https://credentials.example.com/identity_credential",
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
  client_id: "did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7",
  client_metadata: {
    vp_formats: {
      "dc+sd-jwt": {
        alg: ["EdDSA", "ES256"],
      },
    },
  },
  presentation_definition: PRESENTATION_DEFINITION,
  response_uri: "http://localhost:9001/response",
  response_mode: "direct_post",
  response_type: "vp_token",
  nonce: "YztANglRdmP4ChxsrcS8UcGYoPWwkgiUImkBrQmgWkU",
  state: STATE,
};

export const AUTH_REQUEST_WITH_TRANSACTION_DATA: CommonAuthorizationRequest = {
  transaction_data: [
    {
      type: "type1",
      credential_ids: ["Fake-identity"],
      transaction_data_hashes_alg: ["sha-256"],
    },
  ],
  ...AUTH_REQUEST,
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
  definition_id: "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
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
