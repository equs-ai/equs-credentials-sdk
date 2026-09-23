import {
  _PresentationSession,
  EqusSdkError,
  Alg,
  AuthorizationRequestMetadata,
  AuthorizationResponse,
  AuthorizationResponseObject,
  AuthorizationResponseType,
  AuthResponseOptions,
  buildDelegateTransactionData,
  ClientId,
  contextEnsuredNonceHandler,
  CredentialVerificationMetadata,
  DelegationRequest,
  InMemKms,
  KeyHandle,
  KeyType,
  Kms,
  LocalNonceHandler,
  OID4VPVerifierBuilder,
  PassAuthRequestObjectType,
  ReqwestHttpClient,
  ResolvedPresentationQuery,
  X509Variant,
  TransactionDataItem,
  TransactionDataResponse,
  VpProtocolError,
  WalletMetadata,
} from "../../";
import {
  AUTH_RESPONSE_JWE,
  CLAIMS,
  DCQL,
  DELEGATE_JWK,
  DSD_JWT_GRANT_CRED_ID,
  DSD_JWT_GRANT_CREDENTIAL,
  DSD_JWT_GRANT_NONCE,
  DSD_JWT_GRANT_RPQ,
  DSD_JWT_GRANT_TD_HASHES,
  DSD_JWT_GRANT_TRANSACTION_DATA,
  DSD_JWT_GRANT_VP_TOKEN,
  PRESENTATION_DEFINITION,
  PRESENTATION_QUERY,
  PRESENTATION_QUERY_FOR_DCQL,
  PRESENTATION_SUBMISSION,
  SAMPLE_ROOT_X509_PEM,
  STATE,
  VP,
  WALLET_METADATA_WITHOUT_X509,
  X509_SAN_DNS_CERT_PEM,
  X509_SAN_DNS_CLIENT_ID,
  X509_SAN_DNS_NAME,
  X509_SAN_DNS_PRIVATE_KEY_PEM,
} from "./fixtures";
import { createDidAndKeyMetadata } from "../utils";
import { util as jose } from "node-jose";
import * as crypto from "node:crypto";

describe("OID4VP Verifier: ", () => {
  it("create Authorization Request by Value", async () => {
    const verifier = await buildVerifier();

    const authResponseOptions: AuthResponseOptions = {
      mode: "direct_post",
      type: "vp_token",
      submissionUri: "http://localhost:9001/response",
      state: STATE,
    };

    const authorizationRequestMetadata: AuthorizationRequestMetadata = {
      authResponseOptions: authResponseOptions,
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByValue,
      },
    };
    const authReqByValue = await verifier.createAuthorizationRequest(
      PRESENTATION_QUERY,
      authorizationRequestMetadata,
      null,
    );

    const decodedPayload = atob(authReqByValue.authorizationRequestJwt.split(".")[1]);
    const expected_state = JSON.parse(decodedPayload)["state"];

    expect(authReqByValue.authorizationRequestUri).toContain("request=eyJh");
    expect(authReqByValue.session.nonce?.length).toBeTruthy();
    expect(authReqByValue.session.resolvedPresentationQuery.presentation_definition).toMatchObject(
      PRESENTATION_DEFINITION,
    );
    expect(expected_state).toEqual(STATE);
  });

  it("create Authorization Request by Value with DCQL", async () => {
    const verifier = await buildVerifier();

    const authResponseOptions: AuthResponseOptions = {
      mode: "direct_post",
      type: "vp_token",
      submissionUri: "http://localhost:9001/response",
      state: STATE,
    };

    const authorizationRequestMetadata: AuthorizationRequestMetadata = {
      authResponseOptions: authResponseOptions,
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByValue,
      },
    };
    const authReqByValue = await verifier.createAuthorizationRequest(
      PRESENTATION_QUERY_FOR_DCQL,
      authorizationRequestMetadata,
      null,
    );

    const decodedPayload = atob(authReqByValue.authorizationRequestJwt.split(".")[1]);
    const expected_state = JSON.parse(decodedPayload)["state"];

    expect(authReqByValue.authorizationRequestUri).toContain("request=eyJh");
    expect(authReqByValue.session.nonce?.length).toBeTruthy();
    expect(authReqByValue.session.resolvedPresentationQuery.dcql_query).toMatchObject(DCQL);
    expect(expected_state).toEqual(STATE);
  });

  it("create signed Authorization Request by Value with DCQL and dc_api/dc_api.jwt response mode", async () => {
    const verifier = await buildVerifier();
    const response_modes = ["dc_api", "dc_api.jwt"];

    for (const responseMode of response_modes) {
      const authResponseOptions: AuthResponseOptions = {
        mode: responseMode,
        type: "vp_token",
        state: STATE,
      };
      const expectedOrigins = ["https://example.verifier.org"];
      const authorizationRequestMetadata: AuthorizationRequestMetadata = {
        authResponseOptions: authResponseOptions,
        passAuthRequestObject: {
          type: PassAuthRequestObjectType.ByValue,
        },
        expectedOrigins: expectedOrigins,
      };

      const authReqByValue = await verifier.createAuthorizationRequest(
        PRESENTATION_QUERY_FOR_DCQL,
        authorizationRequestMetadata,
        null,
      );

      expect(authReqByValue.authorizationRequestUri).toContain("request=eyJh");
      expect(authReqByValue.session.nonce?.length).toBeTruthy();
      expect(authReqByValue.session.resolvedPresentationQuery.dcql_query).toMatchObject(DCQL);

      const decodedPayload = atob(authReqByValue.authorizationRequestJwt.split(".")[1]);
      const authReqJson = JSON.parse(decodedPayload);

      expect(authReqJson["state"]).toEqual(STATE);
      expect(authReqJson["response_mode"]).toEqual(responseMode);
      expect(authReqJson["expected_origins"]).toEqual(expectedOrigins);
      expect(authReqJson["response_uri"]).toBeFalsy();
      expect(authReqJson["redirect_uri"]).toBeFalsy();
    }
  });

  it("create Authorization Request by Reference", async () => {
    const verifier = await buildVerifier();

    const authResponseOptions: AuthResponseOptions = {
      mode: "direct_post",
      type: "vp_token",
      submissionUri: "http://localhost:9001/response",
      state: STATE,
    };

    const authorizationRequestMetadata: AuthorizationRequestMetadata = {
      authResponseOptions: authResponseOptions,
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByReference,
        requestUri: "http://localhost:9001/request",
      },
    };
    const authReqByReference = await verifier.createAuthorizationRequest(
      PRESENTATION_QUERY,
      authorizationRequestMetadata,
      null,
    );

    expect(authReqByReference.authorizationRequestUri).toContain("request_uri=http%3A%2F%2Flocalhost%3A9001%2Frequest");
    expect(authReqByReference.session.nonce?.length).toBeTruthy();
    expect(authReqByReference.session.resolvedPresentationQuery.presentation_definition).toMatchObject(
      PRESENTATION_DEFINITION,
    );
  });

  it("create Authorization Request with TransactionData", async () => {
    const verifier = await buildVerifier();

    const authResponseOptions: AuthResponseOptions = {
      mode: "direct_post",
      type: "vp_token",
      submissionUri: "http://localhost:9001/response",
      state: STATE,
    };

    const transactionData: Array<TransactionDataItem> = [
      {
        type: "some_type",
        credential_ids: ["1", "2"],
        transaction_data_hashes_alg: ["sha-256"],
      },
    ];

    const authorizationRequestMetadata: AuthorizationRequestMetadata = {
      authResponseOptions: authResponseOptions,
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByReference,
        requestUri: "http://localhost:9001/request",
      },
      transactionData,
    };

    const authReqByReference = await verifier.createAuthorizationRequest(
      PRESENTATION_QUERY,
      authorizationRequestMetadata,
      null,
    );
    const transactionDataAsBase64 =
      "eyJjcmVkZW50aWFsX2lkcyI6WyIxIiwiMiJdLCJ0cmFuc2FjdGlvbl9kYXRhX2hhc2hlc19hbGciOlsic2hhLTI1NiJdLCJ0eXBlIjoic29tZV90eXBlIn0";
    const jwt = authReqByReference.authorizationRequestJwt.split(".")[1];
    expect(jose.base64url.decode(jwt).toString()).toContain(transactionDataAsBase64);
    expect(jose.base64url.decode(jwt).toString()).toContain("transaction_data");
  });

  it("verify Authorization Response", async () => {
    const verifier = await buildVerifier("did:key:zDnaehdgostuLiVRhFWfn4d6fr76dQx7DxSJnTzBD3jv832DP");

    const rpq: ResolvedPresentationQuery = {
      presentation_definition: PRESENTATION_QUERY.presentation_definition,
      dcql_query: PRESENTATION_QUERY.dcql_query,
    };
    const session: _PresentationSession = {
      nonce: "n-07kSJUQNwlPISE3jc8QxEia2MHTqewM3WyVx-4XlM",
      resolvedPresentationQuery: rpq,
      authorizationRequestJwt: "",
    };

    const auth_response_object: AuthorizationResponseObject = {
      vpToken: VP,
      presentationSubmission: PRESENTATION_SUBMISSION,
      state: STATE,
    };

    const auth_response: AuthorizationResponse = {
      type: AuthorizationResponseType.Plain,
      object: auth_response_object,
    };

    const verificationMetadata: CredentialVerificationMetadata = {};
    const claims = await verifier.verifyPresentation(auth_response, session, verificationMetadata);

    expect(claims).toEqual(CLAIMS);
  });

  it("verify Authorization Response with transaction data", async () => {
    const verifier = await buildVerifier("did:key:zDnaehdgostuLiVRhFWfn4d6fr76dQx7DxSJnTzBD3jv832DP");

    const rpq: ResolvedPresentationQuery = {
      presentation_definition: PRESENTATION_QUERY.presentation_definition,
      dcql_query: PRESENTATION_QUERY.dcql_query,
    };
    const session: _PresentationSession = {
      nonce: "n-07kSJUQNwlPISE3jc8QxEia2MHTqewM3WyVx-4XlM",
      resolvedPresentationQuery: rpq,
      authorizationRequestJwt: "",
    };
    const transactionData: Array<TransactionDataItem> = [
      {
        type: "some_type",
        credential_ids: ["1", "2"],
        transaction_data_hashes_alg: ["sha-256"],
      },
    ];

    const transactionDataResponse: TransactionDataResponse = {
      hashes: ["1lG1y0zepp3P6CCIWp2aE0JxF83WikkwEqngDVqRJPs"],
    };

    const auth_response_object: AuthorizationResponseObject = {
      vpToken: VP,
      presentationSubmission: PRESENTATION_SUBMISSION,
      state: STATE,
      transactionDataResponse: transactionDataResponse,
    };

    const auth_response: AuthorizationResponse = {
      type: AuthorizationResponseType.Plain,
      object: auth_response_object,
    };

    const verificationMetadata: CredentialVerificationMetadata = {
      transactionData,
    };
    const claims = await verifier.verifyPresentation(auth_response, session, verificationMetadata);

    expect(claims).toEqual(CLAIMS);
  });

  it("create Authorization Request with TransactionData of type delegate", async () => {
    const verifier = await buildVerifier();

    const authResponseOptions: AuthResponseOptions = {
      mode: "direct_post",
      type: "vp_token",
      submissionUri: "http://localhost:9001/response",
      state: STATE,
    };

    const delegateItem = await buildDelegateTransactionData(
      DelegationRequest.holderBinding([DSD_JWT_GRANT_CRED_ID], DELEGATE_JWK, { purchase_id: "p-42" }),
      contextEnsuredNonceHandler(new LocalNonceHandler()),
    );

    expect(delegateItem.type).toEqual("delegate");
    expect(delegateItem.credential_ids).toEqual([DSD_JWT_GRANT_CRED_ID]);
    expect(delegateItem).not.toHaveProperty("content");
    expect(delegateItem.format).toEqual("dSD-JWT+KB");

    const authorizationRequestMetadata: AuthorizationRequestMetadata = {
      authResponseOptions: authResponseOptions,
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByValue,
      },
      transactionData: [delegateItem],
    };

    const authReqByValue = await verifier.createAuthorizationRequest(
      PRESENTATION_QUERY,
      authorizationRequestMetadata,
      null,
    );

    const jwt = authReqByValue.authorizationRequestJwt.split(".")[1];
    const decodedPayload = jose.base64url.decode(jwt).toString();
    expect(decodedPayload).toContain("transaction_data");

    const decodedItem = jose.base64url.decode(JSON.parse(decodedPayload).transaction_data[0]).toString();
    expect(decodedItem).toContain("delegate");
    expect(decodedItem).toContain(DSD_JWT_GRANT_CRED_ID);
  });

  it("delegate transaction data disclosure carries a fresh salt and the delegate payload", async () => {
    const nonceHandler = contextEnsuredNonceHandler(new LocalNonceHandler());

    const item = await buildDelegateTransactionData(
      DelegationRequest.holderBinding([DSD_JWT_GRANT_CRED_ID], DELEGATE_JWK, { purchase_id: "p-42" }),
      nonceHandler,
    );

    const [salt, payload] = decodeDelegatePayloadDisclosure(item);
    expect(salt.length).toBeGreaterThan(0);
    expect(payload.purchase_id).toEqual("p-42");
    expect(payload.cnf).toEqual({ jwk: DELEGATE_JWK });

    const other = await buildDelegateTransactionData(
      DelegationRequest.open([DSD_JWT_GRANT_CRED_ID]),
      nonceHandler,
    );
    const [otherSalt] = decodeDelegatePayloadDisclosure(other);
    expect(otherSalt).not.toEqual(salt);
  });

  it("builds a terminal delegate item and rejects invalid delegation requests", async () => {
    const nonceHandler = contextEnsuredNonceHandler(new LocalNonceHandler());

    const terminal = await buildDelegateTransactionData(DelegationRequest.open([DSD_JWT_GRANT_CRED_ID]), nonceHandler);
    expect(terminal.format).toEqual("dSD-JWT");
    const [, terminalPayload] = decodeDelegatePayloadDisclosure(terminal);
    expect(terminalPayload.cnf).toBeUndefined();

    // `DelegationRequest.holderBinding`/`.open` can't be called without the arguments their
    // format requires, so the TypeScript compiler already refuses a malformed request. `as
    // any` simulates an untyped JS caller (or a bypassed type-check) hand-writing the wire
    // shape directly, to assert the native side still rejects it at runtime.
    await expect(
      buildDelegateTransactionData({ credentialIds: ["c1"], format: "dSD-JWT+KB" } as any, nonceHandler),
    ).rejects.toThrow();

    await expect(
      buildDelegateTransactionData(
        DelegationRequest.open(["c1"], { cnf: { jwk: DELEGATE_JWK } }),
        nonceHandler,
      ),
    ).rejects.toThrow();

    await expect(
      buildDelegateTransactionData({ credentialIds: ["c1"], format: "dSD-JWT+KB " } as any, nonceHandler),
    ).rejects.toThrow();
  });

  it("verify and extract a dSD-JWT delegation grant", async () => {
    const verifier = await buildVerifier();

    const rpq = DSD_JWT_GRANT_RPQ as unknown as ResolvedPresentationQuery;
    const session: _PresentationSession = {
      nonce: DSD_JWT_GRANT_NONCE,
      resolvedPresentationQuery: rpq,
      authorizationRequestJwt: "",
    };

    const auth_response_object: AuthorizationResponseObject = {
      vpToken: DSD_JWT_GRANT_VP_TOKEN,
      transactionDataResponse: { hashes: DSD_JWT_GRANT_TD_HASHES },
    };
    const auth_response: AuthorizationResponse = {
      type: AuthorizationResponseType.Plain,
      object: auth_response_object,
    };

    const verificationMetadata: CredentialVerificationMetadata = {
      transactionData: DSD_JWT_GRANT_TRANSACTION_DATA,
    };

    const verified = await verifier.verifyAndExtractPresentation(auth_response, session, verificationMetadata);

    // A grant's verified claims keep the halves apart: `issued_vc` plus
    // `delegations` (one array of disclosed alternatives per hop).
    const cred = (verified.claims.vp_token as Record<string, Array<Record<string, unknown>>>)[DSD_JWT_GRANT_CRED_ID][0];
    expect((cred.issued_vc as Record<string, unknown>).iss).toBeDefined();
    const delegations = cred.delegations as Array<Array<Record<string, unknown>>>;
    const lastHop = delegations[delegations.length - 1];
    expect(lastHop.map((alternative) => alternative.scope)).toContain("limited");

    // The raw dSD-JWT grant is returned so the Delegate Holder can store it.
    const presentations = verified.presentations[DSD_JWT_GRANT_CRED_ID];
    expect(presentations).toHaveLength(1);
    expect(presentations[0]).toEqual(DSD_JWT_GRANT_CREDENTIAL);
    expect(presentations[0] as string).toMatch(/~$/);
  });

  it("build verifier with trusted root certificate", async () => {
    const kms = new InMemKms();
    const nonceGenerator = new LocalNonceHandler();
    const { keyMetadata } = await createDidAndKeyMetadata(kms);
    const encoder = new TextEncoder();

    await new OID4VPVerifierBuilder(
      kms,
      nonceGenerator,
      keyMetadata,
      ClientId.fromDid("did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX"),
    )
      .withHttpClient(ReqwestHttpClient.insecure())
      .addTrustedRootCertificate(encoder.encode(SAMPLE_ROOT_X509_PEM))
      .build();
  });

  it("create Authorization Request with the x509_san_dns client id", async () => {
    const verifier = await buildX509Verifier();

    const authorizationRequestMetadata: AuthorizationRequestMetadata = {
      authResponseOptions: {
        mode: "direct_post",
        type: "vp_token",
        submissionUri: "http://localhost:9001/response",
        state: STATE,
      },
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByValue,
      },
    };

    // No wallet metadata — the cross-device case. The SDK default has to
    // advertise the x509 prefixes for this to be accepted.
    const authRequest = await verifier.createAuthorizationRequest(PRESENTATION_QUERY, authorizationRequestMetadata);

    // The certificate chain is carried in the request JWT `x5c` header, and the
    // client id is the leaf certificate's SAN DNS name.
    const [header, payload] = authRequest.authorizationRequestJwt
      .split(".")
      .slice(0, 2)
      .map((part) => JSON.parse(atob(part)));

    expect(header.x5c).toHaveLength(1);
    expect(payload.client_id).toEqual(X509_SAN_DNS_CLIENT_ID);
  });

  it("create Authorization Request with the x509_hash client id", async () => {
    // An x509_hash client id can only be derived from the leaf certificate.
    const clientId = ClientId.fromX509CertificateChain(x509CertificateChain(), X509Variant.Hash);
    const verifier = await buildX509Verifier(clientId);

    const authorizationRequestMetadata: AuthorizationRequestMetadata = {
      authResponseOptions: {
        mode: "direct_post",
        type: "vp_token",
        submissionUri: "http://localhost:9001/response",
        state: STATE,
      },
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByValue,
      },
    };

    const authRequest = await verifier.createAuthorizationRequest(PRESENTATION_QUERY, authorizationRequestMetadata);

    const [header, payload] = authRequest.authorizationRequestJwt
      .split(".")
      .slice(0, 2)
      .map((part) => JSON.parse(atob(part)));

    expect(header.x5c).toHaveLength(1);
    // Reaching here at all proves the derived client id equals the one the
    // verifier computes from the same chain — it rejects any other.
    expect(payload.client_id).toMatch(/^x509_hash:.+/);
  });

  it("derives an x509_san_dns client id from the certificate chain", async () => {
    const clientId = ClientId.fromX509CertificateChain(x509CertificateChain(), X509Variant.SanDns);
    const verifier = await buildX509Verifier(clientId);

    const authRequest = await verifier.createAuthorizationRequest(PRESENTATION_QUERY, {
      authResponseOptions: {
        mode: "direct_post",
        type: "vp_token",
        submissionUri: "http://localhost:9001/response",
        state: STATE,
      },
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByValue,
      },
    });

    const payload = JSON.parse(atob(authRequest.authorizationRequestJwt.split(".")[1]));

    // Same value as fromX509SanDns("verifier.example"), read off the leaf's SAN.
    expect(payload.client_id).toEqual(X509_SAN_DNS_CLIENT_ID);
  });

  it("rejects a certificate chain that cannot be parsed", () => {
    expect(() => ClientId.fromX509CertificateChain(new TextEncoder().encode("not a pem"), X509Variant.Hash)).toThrow();
  });

  it("reads a client id back as the value it represents", () => {
    const sanDns = ClientId.fromX509SanDns(X509_SAN_DNS_NAME);

    expect(sanDns.fullId).toEqual(X509_SAN_DNS_CLIENT_ID);
    expect(sanDns.prefix).toEqual("x509_san_dns");
    expect(sanDns.id).toEqual(X509_SAN_DNS_NAME);

    // Every constructor round-trips through the string form.
    expect(new ClientId(sanDns.fullId).fullId).toEqual(sanDns.fullId);

    const did = ClientId.fromDid("did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX");
    expect(did.prefix).toEqual("decentralized_identifier");
    expect(did.id).toEqual("did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX");

    // A bare string is pre-registered, and reads back carrying that prefix.
    const preRegistered = new ClientId("acme-verifier");
    expect(preRegistered.prefix).toEqual("pre-registered");
    expect(preRegistered.id).toEqual("acme-verifier");
    expect(preRegistered.fullId).toEqual("pre-registered:acme-verifier");
  });

  it("surfaces an x509_hash identity change when the certificate rotates", () => {
    const before = ClientId.fromX509CertificateChain(x509CertificateChain(), X509Variant.Hash);
    const rotated = ClientId.fromX509CertificateChain(new TextEncoder().encode(SAMPLE_ROOT_X509_PEM), X509Variant.Hash);

    // Same chain, same identity — so a stored value can be compared directly.
    expect(ClientId.fromX509CertificateChain(x509CertificateChain(), X509Variant.Hash).fullId).toEqual(before.fullId);

    // A different leaf is a different relying party under x509_hash.
    expect(rotated.fullId).not.toEqual(before.fullId);
    expect(before.prefix).toEqual("x509_hash");
    expect(rotated.prefix).toEqual("x509_hash");
  });

  it("rejects an x509_san_dns client id whose SAN DNS name does not match the certificate", async () => {
    const verifier = await buildX509Verifier(ClientId.fromX509SanDns("other.example"));

    const authorizationRequestMetadata: AuthorizationRequestMetadata = {
      authResponseOptions: {
        mode: "direct_post",
        type: "vp_token",
        submissionUri: "http://localhost:9001/response",
        state: STATE,
      },
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByValue,
      },
    };

    await expect(verifier.createAuthorizationRequest(PRESENTATION_QUERY, authorizationRequestMetadata)).rejects.toThrow(
      /does not match the configured client_id/,
    );
  });

  it("rejects a certificate that does not certify the verifier's signing key", async () => {
    // A different key, so the fixed certificate no longer certifies it.
    const foreignKey = crypto
      .generateKeyPairSync("ec", { namedCurve: "prime256v1" })
      .privateKey.export({ format: "pem", type: "pkcs8" }) as string;
    const verifier = await buildX509Verifier(undefined, staticKeyKms(foreignKey));

    const authorizationRequestMetadata: AuthorizationRequestMetadata = {
      authResponseOptions: {
        mode: "direct_post",
        type: "vp_token",
        submissionUri: "http://localhost:9001/response",
        state: STATE,
      },
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByValue,
      },
    };

    await expect(verifier.createAuthorizationRequest(PRESENTATION_QUERY, authorizationRequestMetadata)).rejects.toThrow(
      /does not certify the verifier signing key/,
    );
  });

  it("rejects an x509_san_dns client id when the wallet does not advertise the prefix", async () => {
    const verifier = await buildX509Verifier();

    const authorizationRequestMetadata: AuthorizationRequestMetadata = {
      authResponseOptions: {
        mode: "direct_post",
        type: "vp_token",
        submissionUri: "http://localhost:9001/response",
        state: STATE,
      },
      passAuthRequestObject: {
        type: PassAuthRequestObjectType.ByValue,
      },
    };

    await expect(
      verifier.createAuthorizationRequest(
        PRESENTATION_QUERY,
        authorizationRequestMetadata,
        WALLET_METADATA_WITHOUT_X509 as WalletMetadata,
      ),
    ).rejects.toThrow();
  });

  it("builds verifier with custom KMS that supports JWE decryption and uses it", async () => {
    const innerKms = new InMemKms();
    const kms = new (class JweKms implements Kms {
      decryptCalledWith: string;
      create(kt: KeyType): Promise<string> {
        return innerKms.create(kt);
      }
      async get(kid: string): Promise<KeyHandle> {
        if (kid == "ecdsa-kid") {
          // this kid is used in AUTH_RESPONSE_JWT fixture
          const kid_1 = await innerKms.create(KeyType.P256);
          return await innerKms.get(kid_1);
        }
        return await innerKms.get(kid);
      }
      getByPublicKey(pk: Uint8Array): Promise<KeyHandle> {
        return innerKms.getByPublicKey(pk);
      }
      // tested decrypt method
      async decrypt(jwe: string): Promise<Record<string, any>> {
        this.decryptCalledWith = jwe;
        return { vp_token: "fake token" };
      }
    })();

    const nonceGenerator = new LocalNonceHandler();
    const { keyMetadata } = await createDidAndKeyMetadata(kms);

    let verifier = await new OID4VPVerifierBuilder(
      kms,
      nonceGenerator,
      keyMetadata,
      ClientId.fromDid("did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX"),
    )
      .withHttpClient(ReqwestHttpClient.insecure())
      .build();

    const auth_response: AuthorizationResponse = {
      type: AuthorizationResponseType.Jwe,
      jwe: AUTH_RESPONSE_JWE,
    };
    const rpq: ResolvedPresentationQuery = {
      presentation_definition: PRESENTATION_QUERY.presentation_definition,
      dcql_query: PRESENTATION_QUERY.dcql_query,
    };
    const session: _PresentationSession = {
      nonce: "n-07kSJUQNwlPISE3jc8QxEia2MHTqewM3WyVx-4XlM",
      resolvedPresentationQuery: rpq,
      authorizationRequestJwt: "",
    };
    const transactionData: Array<TransactionDataItem> = [
      {
        type: "some_type",
        credential_ids: ["1", "2"],
        transaction_data_hashes_alg: ["sha-256"],
      },
    ];
    const verificationMetadata: CredentialVerificationMetadata = {
      transactionData,
    };

    try {
      await verifier.verifyPresentation(auth_response, session, verificationMetadata);
    } catch (e) {
      let equs_sdk_err: EqusSdkError = JSON.parse(e.message);
      // Expect that the SDK received Authorization Response with vp_token parameter but fails to get transactional data
      expect(equs_sdk_err.code).toEqual(VpProtocolError.InvalidTransactionData);
    }

    expect(kms.decryptCalledWith).toEqual(auth_response.jwe);
  });
});

async function buildVerifier(clientId = "did:key:zDnaeagvW2eDWc2yVw7B98ovcJ8jddn7T9Mh3y5Vikys6y4kX") {
  const kms = new InMemKms();
  const nonceGenerator = new LocalNonceHandler();
  const { keyMetadata } = await createDidAndKeyMetadata(kms);

  return await new OID4VPVerifierBuilder(kms, nonceGenerator, keyMetadata, ClientId.fromDid(clientId))
    .withHttpClient(ReqwestHttpClient.insecure())
    .build();
}

function decodeDelegatePayloadDisclosure(item: TransactionDataItem): [string, Record<string, any>] {
  const decoded = jose.base64url.decode((item as any).delegate_payload_disclosure).toString();
  return JSON.parse(decoded);
}

/**
 * A KMS holding exactly one key: the one {@link X509_SAN_DNS_CERT_PEM}
 * certifies. `InMemKms` generates a fresh key per run, which no fixed
 * certificate could ever match.
 */
function staticKeyKms(privateKeyPem = X509_SAN_DNS_PRIVATE_KEY_PEM): Kms {
  const privateKey = crypto.createPrivateKey(privateKeyPem);
  const publicKey = crypto.createPublicKey(privateKeyPem);
  const jwk = publicKey.export({ format: "jwk" });

  const keyHandle: KeyHandle = {
    alg: Alg.ES256,
    jwk: JSON.stringify(jwk),
    // Uncompressed SEC1 point, as the SDK expects for P-256.
    pubKey: Array.from(
      Buffer.concat([Buffer.from([0x04]), Buffer.from(jwk.x!, "base64url"), Buffer.from(jwk.y!, "base64url")]),
    ),
    // JWS signatures are raw r||s, not the DER encoding node defaults to.
    sign: async (payload) => crypto.sign(null, payload, { key: privateKey, dsaEncoding: "ieee-p1363" }),
    verify: async (data, signature) => {
      const ok = crypto.verify(null, data, { key: publicKey, dsaEncoding: "ieee-p1363" }, signature);
      if (!ok) {
        throw new Error("invalid signature");
      }
    },
  };

  return {
    create: async () => "x509-verifier-key",
    get: async () => keyHandle,
    getByPublicKey: async () => keyHandle,
  };
}

function x509CertificateChain(): Uint8Array {
  return new TextEncoder().encode(X509_SAN_DNS_CERT_PEM);
}

async function buildX509Verifier(
  clientId: ClientId = ClientId.fromX509SanDns(X509_SAN_DNS_NAME),
  kms: Kms = staticKeyKms(),
) {
  const nonceGenerator = new LocalNonceHandler();
  const { keyMetadata } = await createDidAndKeyMetadata(kms);

  return await new OID4VPVerifierBuilder(kms, nonceGenerator, keyMetadata, clientId)
    .withHttpClient(ReqwestHttpClient.insecure())
    .withX509CertificateChain(x509CertificateChain())
    .build();
}
