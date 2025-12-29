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
export const AUTH_RESPONSE_JWE = "eyJraWQiOiJlY2RzYS1raWQiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2IiwiYWxnIjoiRUNESC1FUyIsImFwdSI6ImMyOXRaVjl1YjI1alpRIiwiYXB2IjoiYzI5dFpWOXViMjVqWlEiLCJlcGsiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJpWC1sSElkVmh1a3dYWnVfS3loaHhRRnotekZNeFlTUE13UFpyWmppaEZJIiwieSI6ImtrNVdSejVLOWt0UlRVdEdUMmVndFBYeUV4ZnZXZWxxUHZIdkhiVml1MXcifX0..LL66qVEykIcihEcjDH7G8A.Z1NY2cOeK8cXvUTSou0Eg-jngcy6JaX9w5e4OmxxyyLzjSSSvUHc7j5OIBv53oUQnUXot2j-RrK6tshXB_tb2AaZH-p6Y5rmDoTpwpc96GhFzTodV18qXFtCLZVkAaBJz5Xdev9k_MLh1kw_OmdTmpUATYHTwfI0lXpK19spBJ56U6m1r3EZND3HvBcRSXGusIOhpW8XwCxf2GwUSEspjSPwlPpSmw6jiEsL5QDdlMOU6x7hmiptig5IeHmShZ2yM65Qsu0E9FXhFC2bFj3sjq738tfsiCt1TcUTeA0TbSgLywpSSm_tUi9fCZ7nE53RZmHrCRt4nvKdMbztV7fZh_50gHGOfLmuN5sU409yIbdZybRSlDPafCZOHNHvKDViWLcYCUHs64fy3Du2zYzFzY5hQmVxS_IcLNTzTJ6Pm69xph0s0gmlI98YGZ4PDzOaAkUimrUwSkCptJBU7gbFc9cIsgiWY1JtNvpj48e6FtC1LLD0tKC3IwrE-PZ0-VHYRtJPr-aHNAxaJKDqU2tVYakIJ6RzPM6yA7nO0L6mRpRFARZaBG1esUWWZ4UompeZtCxjIBF2ezvv-m7Rr6DhB9pI2B6ghbOYnv8KFDXnM7mnmin85dsFPblof0SKPWocgRslcF9YY4MYhYPjM7NKcjOcwb6Sq6iQZ4eUdmdo8KG3Z0KSL28LW4SJLBDp_ROtRW5H4bE2LSIxjqVvk6AxgsS_8XxjcXKlyAjNErytSpU__M_uqbOnt8NfCnqbH2RVcC9VH8v5GDhhinx_8-pq1K4EfRxZvnlzOaos4K-JmikEhtqfyfUFvrNxUSByCZ57_FrmY49uNVTA9NBRwHDL8FarbKMifc5Xu83p4VdD-CrfonPMAe1bYCHrVuZ_bilbil48T9mBCUobIDtHXSuMQ3vOWFrugH0QevVm3pebnRon9MhJQZYXf3MMCWXsPDhO3qJoVsAd-qHWev9nRos4V430DLLG0XOOovy-VtumQNDXBJXEOf6BCe5EOxM8Kk8gWcgrFH9vbvOisbe_-MHtODiQrxJCSKRR95SnOQGoA4K6VEg55U4MwrhwGlPxnpQG3CN4LU9oqMBCFzR02nywGoB_wDt6wg_rMw9UtFltc8A0mF_gyxzMeHND5uHO-dttrcMZZnjsgtDLYx-tWbhuPK3D3j8pAJ5pm9EQPipV7MSrlxMdMZyJ2Ntgy2H0cXxeIzrfKyHE3492hSTsbKQ1YXOi7NuwhgUdbe2WauLAtQeuOggSuCaMPy2d9n0Ba2KTGb1cbAZsvYcXIwxd0Qe9QndqLTwDFO9N1wLD4IfiA95Vcog_w2LL5DMA6c-C4ViNUpqBQ-mqzeuo-9LPq5NGuHF_HJDgXzdm8--BCrw6wuiJ1I5MllYKTxhbDvt2zex2kr8he3-yLgAI1snHRNyDaeitPirypgDamCjcfDOJxOwh4mGwQk4cmncfRL9EJyCSnDzR_6w02Ipz1gVWax1p_j8QE79d-pi9fULjemDtB4CA1hnDwFGVTYhAdYRw789z6GmqVs6csmzPgf_rBKMvN8VtiV9S6HsRPnvhXQ83c7XOt1Nn98llgRlDCbcOS9SKYupROgyXnzGuJ5ZAj_wCkx6hVaBp9flRvojMVlCG_nu-ve9QWvxcS_DHGjpiSNf9J9xbBJTQHoE6sWwWzDnN-5NglCdW-OXIVNXqB-71Uw3Ia5yH6ocKywTIlwHzoLNY9wf8XP8wshF3d3vjRfzdjUbwALpg1yIMfju1BQ2WQJoru3UGCnhHzx20tcsrW3SOq24F_q86XO3vR_MMkwakNL3wJrSkAsGxd6G-4nwfQxGuovR0PcfugxRuBsL0N_6oFRjVi5pY3_nc6YorazUC_DGVqnh8wAEjP1paJpO1tUtSZN66vFKRFmfHjtLJ3e7TV1K1Cdf9iWLTJOQc6jxBYZ9GEWY_WM0AAgQCe2L0xQlZpjPgMn4CgH21QL9b06rbSe2a6wPlIOoatOWM2g3wTuM_CPenROjVmfZrImq8vwpksxjaVrset7WxlcINqPzg92JWSyFH04pKqo-dq08My_IPEwScplyJZgO7EIMv5mVOORR26hSLnh6YLZYk9bFEGJXXLmY6Zk1NhV769np_O73BUUCmgC9-QHRY_bYDVLu4qnsPIFNJW1M-47mgvBoIBDZMQQoA4xejWJZ8WlRBr4xIDpKvKNQyjYbBpo6YwZlbsMgoLAeDu3no7D_1A3k1sPnnqiF3HlSDzyPgDg_wWcxeyS6ambfTzUqm4qLuENzfqDqJv6MGn4LiHTsF0aSAxklQCJQbqNESqdN_qwC-ivXhMA6HgW2Vv6QJJ7er6hDVQml5ZKGkZz85eFqx1WTW.6kMxrA6ZHunJYr9018UI3g";

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
  "eyJ0eXAiOiJkYytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV5SFZKVjhmOUhjZUpUenNuRmlCOGltRXNXMzY5VjFKVzFjcXRoVWhGM3NDayN6RG5hZXlIVkpWOGY5SGNlSlR6c25GaUI4aW1Fc1czNjlWMUpXMWNxdGhVaEYzc0NrIn0.eyJfc2QiOlsiSU1TcDRQU2hMSUxkVDVnN1dvWHpOUTlBS3N2OUEtMWFoa0YweTRrZDdJZyIsImVUWHlJWnYtODMtejZsRHBudGZuSjZmdjRQX0JUNmtGNzRyYUExYUptNjQiLCJtOHpnaW45TDRWNkpIbTM0TFZ4RWtFVGs3NU9QcUNNYVF3MDduTWwyaHQwIl0sInN1YiI6ImRpZDprZXk6ekRuYWV3MUs0VGttS3VVSk5tTlltbWlhZjlwRHlhVExDNlZHV0FkNW54V3VkaXpIbyIsImRhdGUiOiIwOS8wOS8xOTg5IiwidmN0IjoiaHR0cHM6Ly9jcmVkZW50aWFscy5leGFtcGxlLmNvbS9pZGVudGl0eV9jcmVkZW50aWFsIiwiaWF0IjoxNzY1OTU0NzM5LCJfc2RfYWxnIjoic2hhLTI1NiIsImlzcyI6ImRpZDprZXk6ekRuYWV5SFZKVjhmOUhjZUpUenNuRmlCOGltRXNXMzY5VjFKVzFjcXRoVWhGM3NDayIsImV4cCI6MTc5NzQ5MDczOSwibmJmIjoxNzY1OTU0NzM5LCJjbmYiOnsiandrIjp7Imt0eSI6IkVDIiwiY3J2IjoiUC0yNTYiLCJ4IjoieGtsbm5Wb1ZPU3NxZE5rQXYyeGZZRnhlQmFqTnFpTEFIazYxR05TUWo3byIsInkiOiJDdm5rMktHTU40SjJVcW1xdXBQY0FUQkU1cjIwNk0xMDlXSXlkSXVPNjk4In19fQ.1Z1FpiQdJQIoEu_rH9fmLnEnLkvk9V1NVQEC2mmEfVFxehl8pUCkgC8bN3ej8XAQHELmMFiSr4zudqwNFYn2wQ~WyJVNVRrN3IzTEhWQUd1M1U0ZkxsNnBRIiwgIm5hbWUiLCAiSm9obiJd~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJub25jZSI6Im4tMDdrU0pVUU53bFBJU0UzamM4UXhFaWEyTUhUcWV3TTNXeVZ4LTRYbE0iLCJhdWQiOiJkZWNlbnRyYWxpemVkX2lkZW50aWZpZXI6ZGlkOmtleTp6RG5hZWhkZ29zdHVMaVZSaEZXZm40ZDZmcjc2ZFF4N0R4U0puVHpCRDNqdjgzMkRQIiwic2RfaGFzaCI6IjYtTTkyRzh4TGhOZzlpQVZjZFBuRFk2UkRlcVZiZnJ3a3ljTzNpMmFLbUEiLCJpYXQiOjE3NjU5NTQ3Mzl9.JSnitsTeqm2KNLq-rQMnvhlZm3Th6h8LKb8uXwnWrww0ldbWZ9nx-6TMdxkAUNUjTWEdq6b8-PTwsS-Yv6XtAQ";

export const CLAIMS: Claims = {
  vp_token: {
    "Identity-1": [
      {
        vct: "https://credentials.example.com/identity_credential",
        sub: "did:key:zDnaew1K4TkmKuUJNmNYmmiaf9pDyaTLC6VGWAd5nxWudizHo",
        nbf: 1765954739,
        iss: "did:key:zDnaeyHVJV8f9HceJTzsnFiB8imEsW369V1JW1cqthUhF3sCk",
        iat: 1765954739,
        exp: 1797490739,
        date: "09/09/1989",
        cnf: {
          jwk: {
            kty: "EC",
            crv: "P-256",
            x: "xklnnVoVOSsqdNkAv2xfYFxeBajNqiLAHk61GNSQj7o",
            y: "Cvnk2KGMN4J2UqmqupPcATBE5r206M109WIydIuO698",
          },
        },
        name: "John",
      },
    ],
  },
};

export const SAMPLE_ROOT_X509_PEM = `-----BEGIN CERTIFICATE-----
MIIBZzCCAQ6gAwIBAgIUGaB+RAZje4MNjJqrAlNx1ByAiL8wCgYIKoZIzj0EAwIw
EjEQMA4GA1UEAwwHQ0EgQ2VydDAeFw0yNTEyMTUxMDU2MzBaFw0zNTEyMTMxMDU2
MzBaMBIxEDAOBgNVBAMMB0NBIENlcnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNC
AASVMf5Ykf8dzr46duTAZN3X2iFC1sp1pL15V3u/KDsmPjR21VnK1uv6kDvEziF7
VyIFbvb40t/+c5eB3jg1cMq4o0IwQDAPBgNVHRMBAf8EBTADAQH/MA4GA1UdDwEB
/wQEAwIBhjAdBgNVHQ4EFgQULHoOFFycXvdnCIlsyQiI5izPKkMwCgYIKoZIzj0E
AwIDRwAwRAIgF+H7wT7a95WbiE+DDlZrQ7U3RlCUOMCFqudFRz+K6I4CIAT35kig
4Q1ALvtXiWKDOjZIVxlw5eKQiq0dsd+bXKZE
-----END CERTIFICATE-----`;
