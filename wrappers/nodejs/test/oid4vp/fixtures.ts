import {
  Claims,
  CredentialFormats,
  PresentationDefinition,
  PresentationSubmission,
  CommonAuthorizationRequest,
  PresentationQuery,
  Dcql,
} from "../../";
export const AUTH_REQUEST_JWT =
  "eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVlVEc4OHdwUGhNenVEUnZMUlRUeU5NeUppcDVlNlRMbXNqeXZQaVNZVUZrNyN6RG5hZWVURzg4d3BQaE16dURSdkxSVFR5Tk15SmlwNWU2VExtc2p5dlBpU1lVRms3IiwidHlwIjoiYXBwbGljYXRpb24vb2F1dGgtYXV0aHotcmVxK2p3dCJ9.eyJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJzdGF0ZSI6ImVlYTdiNDhlLTE4NjYtNDFiNC1iZWFlLTAzYjk1ZDQxNjcwYyIsInJlc3BvbnNlX21vZGUiOiJkaXJlY3RfcG9zdCIsIm5vbmNlIjoiWXp0QU5nbFJkbVA0Q2h4c3JjUzhVY0dZb1BXd2tnaVVJbWtCclFtZ1drVSIsImNsaWVudF9tZXRhZGF0YSI6eyJ2cF9mb3JtYXRzIjp7ImRjK3NkLWp3dCI6eyJhbGciOlsiRWREU0EiLCJFUzI1NiJdfX19LCJjbGllbnRfaWQiOiJkaWQ6a2V5OnpEbmFlZVRHODh3cFBoTXp1RFJ2TFJUVHlOTXlKaXA1ZTZUTG1zanl2UGlTWVVGazciLCJjbGllbnRfaWRfc2NoZW1lIjoiZGlkIiwicHJlc2VudGF0aW9uX2RlZmluaXRpb24iOnsiaWQiOiIxYjlkNmJjZC1iYmZkLTRiMmQtOWI1ZC1hYjhkZmJiZDRiZWQiLCJpbnB1dF9kZXNjcmlwdG9ycyI6W3siaWQiOiJJZGVudGl0eS0xIiwiY29uc3RyYWludHMiOnsiZmllbGRzIjpbeyJwYXRoIjpbIiQudmN0Il0sImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiY29uc3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwifSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX0seyJwYXRoIjpbIiQubmFtZSJdLCJvcHRpb25hbCI6dHJ1ZSwicHJlZGljYXRlIjpudWxsLCJpbnRlbnRfdG9fcmV0YWluIjpmYWxzZX1dfSwibmFtZSI6IklkZW50aXR5IFZDIiwicHVycG9zZSI6IldlIHdhbnQgYW4gaWRlbnRpdHkiLCJmb3JtYXQiOnsiZGMrc2Qtand0Ijp7InNkLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2IiwiRWREU0EiXSwia2Itand0X2FsZ192YWx1ZXMiOlsiRVMyNTYiLCJFZERTQSJdfX19XX0sInJlc3BvbnNlX3VyaSI6Imh0dHA6Ly9sb2NhbGhvc3Q6OTAwMS9yZXNwb25zZSJ9.dV0RXxaAJTjnAqGNuPUzMor93gsEkXpoqVRj9-J638lV7mkka4ixXZJ3VIQ0Iqhb7GvCIr0D-7_bWp_xnIYAVA";
export const STATE = "eea7b48e-1866-41b4-beae-03b95d41670c";

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

export const DCQL: Dcql = {
  credentials: [
    {
      id: "1",
      format: "dc+sd-jwt",
      require_cryptographic_holder_binding: true,
      meta: {
        vct_values: ["vct_value"],
      },
      claims: [
        {
          id: "1",
          path: ["work", "email"],
        },
        {
          id: "2",
          path: ["work", "position"],
        },
        {
          id: "3",
          path: ["home", "address"],
        },
      ],
      claim_sets: [
        ["1", "2"],
        ["2", "3"],
      ],
    },
    {
      id: "2",
      format: "ldp_vc",
      require_cryptographic_holder_binding: false,
      meta: {
        type_values: [
          ["type1", "type2"],
          ["type2", "type3"],
        ],
      },
      claims: [
        {
          id: "1",
          path: ["user", "name"],
        },
        {
          id: "2",
          path: ["user", "surname"],
        },
        {
          id: "3",
          path: ["phone", "home-number"],
        },
      ],
      claim_sets: [
        ["1", "2"],
        ["2", "3"],
      ],
    },
  ],
  credential_sets: [
    {
      options: [["1"], ["2"]],
      required: true,
    },
    {
      options: [["1", "2"]],
      required: false,
    },
  ],
};

export const PRESENTATION_QUERY: PresentationQuery = {
  presentation_definition: PRESENTATION_DEFINITION,
};

export const PRESENTATION_QUERY_FOR_DCQL: PresentationQuery = {
  dcql_query: DCQL,
};
export const AUTH_REQUEST: CommonAuthorizationRequest = {
  client_id: "did:key:zDnaeeTG88wpPhMzuDRvLRTTyNMyJip5e6TLmsjyvPiSYUFk7",
  client_metadata: {
    vp_formats_supported: {
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

export const PRESENTATION_SUBMISSION: PresentationSubmission = {
  id: "e18f2155-1235-43e9-8f0c-1f18cf72911a",
  definition_id: "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
  descriptor_map: [
    {
      id: "Identity-1",
      path: "$",
      format: CredentialFormats.VCSDJWT,
    },
  ],
};

export const VC_TYPE = "https://credentials.example.com/identity_credential";

export const VC =
  "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~";
export const VP =
  "eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVuVzZienZ2aUprRGNWdmJpV2R5aERFVVZXQ25jY2tib01KNGNNNTJXZmJBVyN6RG5hZW5XNmJ6dnZpSmtEY1Z2YmlXZHloREVVVldDbmNja2JvTUo0Y001MldmYkFXIn0.eyJfc2QiOlsiRHVORjh0VU41eXVsdDhvQS1ZQXBJYXlFd3NsSkJRRmxrVFhnS2VnOFNrTSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlam1FWmhTVTR4Q0E4U1lzY3oxWDNaNnpCckVHQXJHbXE2TGk2SFBMcHA4NVkiLCJpYXQiOjE3NjA2MDQ1ODksIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZW5XNmJ6dnZpSmtEY1Z2YmlXZHloREVVVldDbmNja2JvTUo0Y001MldmYkFXIiwiZXhwIjoyMDc1OTY0NTg5LCJuYmYiOjE3NjA2MDQ1ODksImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJIejJpTjU5SGJoUjBaY0h6YmhmN1B5U0QxUnpZUWtJcmZDZXZRRTVTWDZzIiwieSI6IllBSDhvMl9ONlBnNFhIaTNLOTRTb0FWTGFJdS1nb2VRbzJXVTVRSXlCRFUifX19.x__3zZMqFV44hDFYyrUmSyiF_zZvBHuhkU3ZYkI-IPpaBAo4wcTn7pkzbcGSXmeWwIoxoeWwyzj_Ji1PUH68sQ~WyJNTEc5Smd2SXlIbVp0bkx1OU5MQXZ3IiwgIm5hbWUiLCAiTWFyayJd~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJpYXQiOjE3NjA2MDQ1ODksImF1ZCI6ImRpZDprZXk6ekRuYWVrS2dYSG5lekx4bjlVQlpQRVVmRGhVM2NNM3pnYTJ2b3VvQ0RvZ3pGVWg0SiIsIm5vbmNlIjoibjBOY0UiLCJzZF9oYXNoIjoiTURGOFRPMTN4bHBUaDZTU2V6ckpDODFNeTZJTmlZbnJQbUs0ZFM3bzdtQSJ9.6JcBiyyE9DkJxg0bKWxSd6-4wBXuAzdZO_gbUWB3YS47VAw_sE5PGB9JJ0GWXTnvVwlYn0Fbh1WfhSBxk6r0jw";

export const CLAIMS: Claims = {
  vp_token: {
    "Identity-1": {
      vct: "https://credentials.example.com/identity_credential",
      sub: "did:key:zDnaejmEZhSU4xCA8SYscz1X3Z6zBrEGArGmq6Li6HPLpp85Y",
      nbf: 1760604589,
      iss: "did:key:zDnaenW6bzvviJkDcVvbiWdyhDEUVWCncckboMJ4cM52WfbAW",
      iat: 1760604589,
      exp: 2075964589,
      cnf: {
        jwk: {
          kty: "EC",
          crv: "P-256",
          x: "Hz2iN59HbhR0ZcHzbhf7PySD1RzYQkIrfCevQE5SX6s",
          y: "YAH8o2_N6Pg4XHi3K94SoAVLaIu-goeQo2WU5QIyBDU",
        },
      },
      name: "Mark",
    },
  },
};
