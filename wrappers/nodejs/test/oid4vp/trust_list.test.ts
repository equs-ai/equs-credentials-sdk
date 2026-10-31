import {
  _PresentationSession,
  AuthorizationResponse,
  AuthorizationResponseType,
  ClientId,
  CredentialClassification,
  Dcql,
  DcqlTrustedAuthority,
  deriveTrustedAuthorityAkis,
  EqusSdkError,
  exportTrustList,
  FixtureKey,
  fixtureLote,
  fixtureMdoc,
  fixtureX509,
  HttpClient,
  HttpRequest,
  HttpResponse,
  InMemKms,
  IssuerTrust,
  LocalNonceHandler,
  OID4VPVerifierBuilder,
  ResolvedPresentationQuery,
  TrustListError,
  TrustListExport,
  VpInternalError,
} from "../../";
import { createDidAndKeyMetadata } from "../utils";

const LOTE_URL = "https://lote.example.com/pid-providers.jwt";
const MDL_CLIENT_ID = "https://verifier.example.com";
const MDL_NONCE = "BQlBqrJEK9Mv7VuBwB3oax3t1-tA84QMrt9hBF75Hu4";
const RFC3339 = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/;

// The fixtures have three P-256 keys, so roles share them; no two sharing a key are matched.
const IACA = fixtureX509(
  JSON.stringify({
    subject: [["CN", "Test IACA"], ["C", "US"]],
    not_before: "2026-01-01",
    not_after: "2046-01-01",
    ca: true,
    key_usages: ["key_cert_sign", "crl_sign"],
  }),
  FixtureKey.Issuer,
);
const DS = fixtureX509(
  JSON.stringify({
    subject: [["CN", "Test DS"], ["C", "US"]],
    not_before: "2026-01-01",
    not_after: "2046-01-01",
    key_usages: ["digital_signature"],
    authority_key_identifier: true,
  }),
  FixtureKey.Verifier,
  IACA,
  FixtureKey.Issuer,
);
const LOTE_SIGNER = fixtureX509(
  JSON.stringify({
    subject: [["CN", "LoTE Scheme Operator"]],
    not_before: "2026-01-01",
    not_after: "2046-01-01",
    key_usages: ["digital_signature"],
  }),
  FixtureKey.Holder,
);

function pidLote(certificates: string[]): string {
  return fixtureLote(
    JSON.stringify({
      lote_type: "http://uri.etsi.org/19602/LoTEType/EUPIDProvidersList",
      sequence_number: 4,
      entities: [{ name: "Test PID Provider", certificates }],
    }),
    LOTE_SIGNER,
    FixtureKey.Holder,
  );
}

/** Serves `body` at `LOTE_URL`, 404 elsewhere, recording the requested URLs. */
function serving(body: string, contentType = "application/jwt"): HttpClient & { requested: string[] } {
  const requested: string[] = [];
  return {
    requested,
    asyncCall: async (request: HttpRequest): Promise<HttpResponse> => {
      requested.push(request.url);
      if (request.url !== LOTE_URL) {
        return { statusCode: 404, headers: {}, body: undefined };
      }
      return { statusCode: 200, headers: { "content-type": contentType }, body };
    },
  };
}

async function exportPidLote(certificates: string[]): Promise<TrustListExport> {
  return exportTrustList(LOTE_URL, "lote_119602", { trustAnchors: [LOTE_SIGNER] }, serving(pidLote(certificates)));
}

async function expectSdkError(promise: Promise<unknown>): Promise<EqusSdkError> {
  try {
    await promise;
  } catch (e) {
    return JSON.parse((e as Error).message);
  }
  throw new Error("expected the call to fail");
}

// The LoTE lists PID providers, so the mDL docType is classified as a PID here (by default it is an
// EAA).
const MDL_AS_PID: CredentialClassification = { pid: ["org.iso.18013.5.1.mDL"] };

async function verifyMdl(
  anchors: TrustListExport | undefined,
  mode?: "enforce" | "report",
  trustedAuthorities?: DcqlTrustedAuthority[],
  configure: (builder: OID4VPVerifierBuilder) => OID4VPVerifierBuilder = (builder) =>
    builder.withCredentialClassification(MDL_AS_PID),
) {
  const kms = new InMemKms();
  const { did, keyMetadata } = await createDidAndKeyMetadata(kms);
  let builder = new OID4VPVerifierBuilder(kms, new LocalNonceHandler(), keyMetadata, ClientId.fromDid(did));
  for (const anchor of anchors?.anchors ?? []) {
    builder = builder.addTrustAnchor({
      pem: anchor.pem,
      sourceRef: anchor.sourceUrl,
      role: anchor.role,
      serviceType: anchor.serviceType,
    });
  }
  if (mode) {
    builder = builder.withIssuerTrustMode(mode);
  }
  const verifier = await configure(builder).build();

  const vp = fixtureMdoc(
    JSON.stringify({
      doc_type: "org.iso.18013.5.1.mDL",
      name_spaces: { "org.iso.18013.5.1": { family_name: "Mustermann", given_name: "Erika" } },
      valid_from: "2026-01-01T00:00:00Z",
      valid_until: "2046-01-01T00:00:00Z",
      x5chain: DS,
      client_id: MDL_CLIENT_ID,
      nonce: MDL_NONCE,
    }),
    FixtureKey.Verifier,
    FixtureKey.Holder,
  );
  const dcql: Dcql = {
    credentials: [
      {
        id: "mDL",
        format: "mso_mdoc",
        meta: { doctype_value: "org.iso.18013.5.1.mDL" },
        claims: [{ path: ["org.iso.18013.5.1", "family_name"] }],
        trusted_authorities: trustedAuthorities,
      },
    ],
  };
  const rpq: ResolvedPresentationQuery = { dcql_query: dcql };
  const session: _PresentationSession = {
    nonce: MDL_NONCE,
    resolvedPresentationQuery: rpq,
    authorizationRequestJwt: "",
  };
  const response: AuthorizationResponse = {
    type: AuthorizationResponseType.Plain,
    object: { vpToken: { mDL: [vp] } },
  };

  return verifier.verifyAndExtractPresentation(response, session, { audience: MDL_CLIENT_ID });
}

describe("exportTrustList", () => {
  it("exports a pinned LoTE with roles, sources and RFC 3339 dates", async () => {
    const exported = await exportPidLote([IACA]);

    expect(exported.unpinned).toBe(false);
    expect(exported.sequenceNumber).toBe(4);
    expect(exported.issuedAt).toMatch(RFC3339);
    expect(exported.nextUpdate).toMatch(RFC3339);
    expect(exported.skippedMembers).toEqual([]);
    expect(exported.excludedServices).toEqual([]);
    expect(exported.anchors).toHaveLength(1);
    const [anchor] = exported.anchors;
    expect(anchor.role).toBe("pid_provider");
    expect(anchor.serviceType).toBeUndefined();
    expect(anchor.sourceUrl).toBe(LOTE_URL);
    expect(anchor.entityName).toBe("Test PID Provider");
    expect(anchor.notAfter).toMatch(RFC3339);
    expect(anchor.sourceNextUpdate).toMatch(RFC3339);
    expect(anchor.pem.trim()).toBe(IACA.trim());
  });

  it("accepts both documented kinds", async () => {
    const lote = await exportTrustList(LOTE_URL, "lote_119602", { trustAnchors: [LOTE_SIGNER] }, serving(pidLote([IACA])));
    // a LoTE is not a TS 119 612 list: the kind is accepted and the document refused
    const lotl = await expectSdkError(
      exportTrustList(LOTE_URL, "lotl_119612", { trustAnchors: [LOTE_SIGNER] }, serving(pidLote([IACA]), "application/vnd.etsi.tsl+xml")),
    );

    expect(lote.anchors).toHaveLength(1);
    expect(lotl.code).toBe(TrustListError.InvalidDocument);
  });

  it("refuses an unknown kind", async () => {
    const error = await expectSdkError(exportTrustList(LOTE_URL, "lote119602" as "lote_119602", { trustAnchors: [LOTE_SIGNER] }));

    expect(error.code).toBe(TrustListError.InvalidOptions);
  });

  it("refuses a root signed by another key than the pinned one", async () => {
    const otherSigner = fixtureX509(JSON.stringify({ subject: [["CN", "Other"]] }), FixtureKey.Issuer);

    const error = await expectSdkError(
      exportTrustList(LOTE_URL, "lote_119602", { trustAnchors: [otherSigner] }, serving(pidLote([IACA]))),
    );

    expect(error.code).toBe(TrustListError.SignerNotTrusted);
    expect(error.message).toMatch(/^trust_list_signer_not_trusted/);
  });

  it("refuses an export without anchors before fetching", async () => {
    const client = serving(pidLote([IACA]));

    const error = await expectSdkError(exportTrustList(LOTE_URL, "lote_119602", undefined, client));

    expect(error.code).toBe(TrustListError.UnpinnedNotAllowed);
    expect(client.requested).toEqual([]);
  });

  it("refuses an http root", async () => {
    const error = await expectSdkError(
      exportTrustList("http://lote.example.com/list.jwt", "lote_119602", { trustAnchors: [LOTE_SIGNER] }),
    );

    expect(error.code).toBe(TrustListError.InvalidUrl);
  });

  it("refuses a leeway over a day", async () => {
    const error = await expectSdkError(
      exportTrustList(LOTE_URL, "lote_119602", { trustAnchors: [LOTE_SIGNER], leewaySeconds: 86401 }),
    );

    expect(error.code).toBe(TrustListError.InvalidOptions);
  });
});

describe("issuer trust from an exported LoTE", () => {
  it("trusts an mDL issued under a listed IACA, echoing the source and role", async () => {
    const verified = await verifyMdl(await exportPidLote([IACA]));

    const expected: Partial<IssuerTrust> = {
      credentialId: "mDL",
      index: 0,
      status: "trusted",
      sourceRef: LOTE_URL,
      role: "pid_provider",
      category: "pid",
    };
    expect(verified.issuerTrust).toHaveLength(1);
    expect(verified.issuerTrust[0]).toMatchObject(expected);
  });

  it("rejects an mDL without anchors under enforce, with the issuer trust as details", async () => {
    const error = await expectSdkError(verifyMdl(undefined));

    expect(error.code).toBe(VpInternalError.IssuerNotTrusted);
    expect(error.message).toBe("Issuer not trusted: `mDL` (no_anchors_configured)");
    // the same shape as `issuerTrust` on success
    expect(error.details).toEqual([
      { credentialId: "mDL", index: 0, status: "not_evaluated", reason: "no_anchors_configured", category: "pid" },
    ]);
  });

  it("reports an mDL issued under an unlisted IACA under report", async () => {
    const unlisted = fixtureX509(
      JSON.stringify({ subject: [["CN", "Other IACA"]], ca: true, key_usages: ["key_cert_sign"] }),
      FixtureKey.Holder,
    );

    const verified = await verifyMdl(await exportPidLote([unlisted]), "report");

    expect(verified.issuerTrust).toEqual([
      { credentialId: "mDL", index: 0, status: "untrusted", reason: "no_anchor_match", category: "pid" },
    ]);
  });
});

describe("issuer trust per credential category", () => {
  it("does not trust an mDL under PID-provider anchors with the default classification", async () => {
    const verified = await verifyMdl(await exportPidLote([IACA]), "report", undefined, (builder) => builder);

    expect(verified.issuerTrust).toEqual([
      { credentialId: "mDL", index: 0, status: "untrusted", reason: "no_anchors_for_category", category: "eaa" },
    ]);
  });

  it("trusts a PID under an anchor without a role by default", async () => {
    const roleless: TrustListExport = { ...(await exportPidLote([IACA])) };
    roleless.anchors = roleless.anchors.map(({ role: _role, ...anchor }) => anchor);

    const verified = await verifyMdl(roleless, "report");

    expect(verified.issuerTrust[0]).toMatchObject({ status: "trusted", category: "pid" });
    expect(verified.issuerTrust[0].role).toBeUndefined();
  });

  it("refuses an unknown role-less anchor scope when the verifier is built", async () => {
    await expect(
      verifyMdl(await exportPidLote([IACA]), "report", undefined, (builder) =>
        builder.withRolelessAnchors("pid_only" as "eaa_only"),
      ),
    ).rejects.toThrow(/unknown role-less anchor scope/);
  });

  it("does not trust a PID under an anchor without a role when those anchor only EAAs", async () => {
    const roleless: TrustListExport = { ...(await exportPidLote([IACA])) };
    roleless.anchors = roleless.anchors.map(({ role: _role, ...anchor }) => anchor);

    const verified = await verifyMdl(roleless, "report", undefined, (builder) =>
      builder.withCredentialClassification(MDL_AS_PID).withRolelessAnchors("eaa_only"),
    );

    expect(verified.issuerTrust).toEqual([
      { credentialId: "mDL", index: 0, status: "untrusted", reason: "no_anchors_for_category", category: "pid" },
    ]);
  });
});

describe("DCQL trusted authorities", () => {
  it("derives the aki value of a listed IACA", async () => {
    const exported = await exportPidLote([IACA]);

    const derived = deriveTrustedAuthorityAkis(
      exported.anchors.map((anchor) => ({ pem: anchor.pem, sourceRef: anchor.sourceUrl, serviceType: anchor.serviceType })),
    );

    expect(derived.values).toHaveLength(1);
    expect(derived.values[0]).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(derived.skipped).toEqual([]);
  });

  it("verifies an mDL under the requested authority", async () => {
    const exported = await exportPidLote([IACA]);
    const { values } = deriveTrustedAuthorityAkis([{ pem: IACA }]);

    const verified = await verifyMdl(exported, "enforce", [{ type: "aki", values }]);

    expect(verified.issuerTrust[0].status).toBe("trusted");
  });

  it("rejects an mDL outside the requested authorities even under report", async () => {
    const exported = await exportPidLote([IACA]);
    const unrelatedIaca = fixtureX509(
      JSON.stringify({ subject: [["CN", "Unrelated IACA"]], ca: true, key_usages: ["key_cert_sign"] }),
      FixtureKey.Holder,
    );
    const { values } = deriveTrustedAuthorityAkis([{ pem: unrelatedIaca }]);
    expect(values).toHaveLength(1);

    const error = await expectSdkError(verifyMdl(exported, "report", [{ type: "aki", values }]));

    expect(error.code).toBe(VpInternalError.TrustedAuthorityMismatch);
    expect(error.message).toMatch(/matches none of the requested trusted authorities$/);
  });
});
