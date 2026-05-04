import { DIDWebVh, ReqwestHttpClient, UniversalDIDResolver } from "../../";
import { generateCACertificate, getLocal, Mockttp } from "mockttp";

// Mirrors the DID and single-entry log fixture from the Rust unit tests
// (src/did/webvh/client.rs). The SCID is the hash of the genesis document;
// keeping the same value lets us re-use the pre-signed log entries.
const DID_SCID = "Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9";
const DID_SINGLE_ENTRY =
  `["1-QmZcQX1TDh7jNrchRqUHQSd8fPRrsAsRHPEd3ycMvL8mva","2025-03-25T15:27:36Z",` +
  `{"method":"did:webvh:0.3","scid":"Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9",` +
  `"updateKeys":["z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV"],"portable":false},` +
  `{"value":{"@context":["https://www.w3.org/ns/did/v1","https://w3id.org/security/jwk/v1"],` +
  `"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com",` +
  `"authentication":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01"],` +
  `"verificationMethod":[{"id":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#auth-key-01",` +
  `"controller":"did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com","type":"JsonWebKey2020",` +
  `"publicKeyJwk":{"kty":"EC","crv":"P-256","x":"GoFNDeVYoSfkPmcPSA1Dz-2Pl7VhEk5jqCh4UZRG3xs",` +
  `"y":"l4QrQoCDMQRXadyVUCa0r6Pj4638lKpwnVT5YVfUsvQ","kid":"auth-key-01"}}],` +
  `"assertionMethod":["did:webvh:Qmcnf4kjGbU3uW3fde3DmFEYjFfYkjcP4nw1kzwoybGqb9:example.com#assert-key-01"]}},` +
  `[{"type":"DataIntegrityProof","cryptosuite":"eddsa-jcs-2022",` +
  `"verificationMethod":"did:key:z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV#z6MkfrBuadijZeorSayJDG9LQi6BBh3Cn73zhqYucWErRjXV",` +
  `"created":"2025-03-25T15:27:36Z","proofPurpose":"authentication",` +
  `"challenge":"1-QmZcQX1TDh7jNrchRqUHQSd8fPRrsAsRHPEd3ycMvL8mva",` +
  `"proofValue":"z3YnCnQT3DPXdBrBh5DdRXFKNskeGEYVaw3Z2z7uHgJKhVaraWaYtP5V36sR4PhWKzEafyvLWX81NBMvWyYf8S1UE"}]]` +
  "\n";

describe("DIDWebVh: ", () => {
  it("can be instantiated with an HTTP client", () => {
    expect(new DIDWebVh(ReqwestHttpClient.insecure())).toBeDefined();
  });
});

describe("UniversalDIDResolver: did:webvh: ", () => {
  it("default resolver does not support did:webvh", async () => {
    const resolver = new UniversalDIDResolver();
    await expect(resolver.resolve(`did:webvh:${DID_SCID}:example.com`)).rejects.toThrow(
      /not supported/i,
    );
  });

  it("withHttpClient resolver does not support did:webvh without explicit registration", async () => {
    const resolver = UniversalDIDResolver.withHttpClient(ReqwestHttpClient.insecure());
    await expect(resolver.resolve(`did:webvh:${DID_SCID}:example.com`)).rejects.toThrow(
      /not supported/i,
    );
  });

  jest.setTimeout(15_000);

  let mockServer: Mockttp;
  let port: number;

  beforeAll(async () => {
    const tls = await generateCACertificate();
    mockServer = getLocal({ https: tls });
    await mockServer.start();
    port = mockServer.port;
  });

  afterAll(async () => {
    await mockServer.stop();
  });

  afterEach(async () => {
    await mockServer.reset();
  });

  it("addResolver makes HTTP request for did:webvh (not 'not supported')", async () => {
    await mockServer.forGet("/.well-known/did.jsonl").thenReply(404, "");
    const resolver = new UniversalDIDResolver();
    resolver.addResolver(new DIDWebVh(ReqwestHttpClient.insecure()));

    let error: Error | null = null;
    try {
      await resolver.resolve(`did:webvh:${DID_SCID}:localhost%3A${port}`);
    } catch (e) {
      error = e as Error;
    }

    expect(error).not.toBeNull();
    expect(error!.message).not.toMatch(/not supported/i);
  });

  it("resolution fails when the server returns HTTP 404", async () => {
    await mockServer.forGet("/.well-known/did.jsonl").thenReply(404, "");
    const resolver = new UniversalDIDResolver();
    resolver.addResolver(new DIDWebVh(ReqwestHttpClient.insecure()));
    await expect(
      resolver.resolve(`did:webvh:${DID_SCID}:localhost%3A${port}`),
    ).rejects.toThrow();
  });

  it("resolution fails when the server returns invalid log content", async () => {
    await mockServer.forGet("/.well-known/did.jsonl").thenReply(200, "not valid jsonl");
    const resolver = new UniversalDIDResolver();
    resolver.addResolver(new DIDWebVh(ReqwestHttpClient.insecure()));
    await expect(
      resolver.resolve(`did:webvh:${DID_SCID}:localhost%3A${port}`),
    ).rejects.toThrow();
  });

  it(
    "resolution fails when the DID document id does not match the resolved DID",
    async () => {
      // The fixture contains id: ...example.com but we resolve against localhost.
      // One-core rejects the mismatch after fetching the log.
      await mockServer.forGet("/.well-known/did.jsonl").thenReply(200, DID_SINGLE_ENTRY);
      const resolver = new UniversalDIDResolver();
      resolver.addResolver(new DIDWebVh(ReqwestHttpClient.insecure()));
      await expect(
        resolver.resolve(`did:webvh:${DID_SCID}:localhost%3A${port}`),
      ).rejects.toThrow();
    },
  );
});
