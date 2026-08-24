import { getLocal } from "mockttp";
import { Utils } from "./fixtures";
import {
  MetadataDiscovery,
  ReqwestHttpClient,
} from "equs-sdk";

describe("Issuer metadata discovery: ", () => {
  const mockServer = getLocal();
  const port = 9000;
  const utils = new Utils({ issuerUrlPort: port });

  beforeAll(async () => {
    await mockServer.start(port);
  });

  beforeEach(async () => {
    mockServer.reset();
    await mockServer.forGet("/.well-known/openid-credential-issuer").thenJson(200, utils.issuerMetadata);
    await mockServer.forGet("/.well-known/oauth-authorization-server/auth").thenJson(200, utils.authServerMetadata);
  });

  afterAll(async () => {
    await mockServer.stop();
  });

  it("discovers Issuer metadata", async () => {
    let metadata = await new MetadataDiscovery(ReqwestHttpClient.insecure()).discoverIssuerMetadata(
      utils.issuerEndpoint,
    );
    expect(metadata).toMatchObject(utils.issuerMetadata);
  });

  it("discovers Authorization Server metadata", async () => {
    let metadata = await new MetadataDiscovery(ReqwestHttpClient.insecure()).discoverAuthServerMetadata(
      utils.authServerEndpoint,
    );
    expect(metadata).toMatchObject(utils.authServerMetadata);
  });
});
