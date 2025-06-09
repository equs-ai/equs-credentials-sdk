// TODO: These tests are accessing an external resource, if the resource is not available it causes tests to failю
//  https://blockchains-inc.atlassian.net/browse/ASDK-438 task has been created to fix these tests.
import { HttpMethod, HttpRequest, ReqwestHttpClient } from "agent-sdk";
import { generateCACertificate, getLocal, Mockttp } from "mockttp";

describe("HTTP Client: ", () => {
  const testForNodeJs = process.env.npm_lifecycle_event === "test:nodejs" ? test : test.skip;
  jest.setTimeout(30 * 1000);
  let mockServer: Mockttp;
  const port = 9000;

  const httpRequest: HttpRequest = {
    url: `http://localhost:${port}/get`,
    method: HttpMethod.GET,
    headers: { accept: "application/json" },
  };
  const httpsRequest: HttpRequest = {
    url: `https://localhost:${port}/get`,
    method: HttpMethod.GET,
    headers: { accept: "application/json" },
  };

  beforeAll(async () => {
    const tls = await generateCACertificate();

    mockServer = getLocal({ https: tls });
    await mockServer.forGet("/get").thenJson(200, {});
    await mockServer.start(port);
  });

  afterAll(async () => {
    await mockServer.stop();
  });

  describe("Secure mode: ", () => {
    testForNodeJs("should success with https url on secure mode", async () => {
      const client = ReqwestHttpClient.insecure();

      const result = await client.asyncCall(httpsRequest);

      expect(result).toBeDefined();
      expect(result.statusCode).toBe(200);
    });

    test.failing("should throw error with http url on secure mode", async () => {
      const client = new ReqwestHttpClient();
      await client.asyncCall(httpRequest);
    });
  });

  describe("Insecure mode: ", () => {
    test("should success with http url on insecure mode", async () => {
      const client = ReqwestHttpClient.insecure();

      const result = await client.asyncCall(httpRequest);

      expect(result).toBeDefined();
      expect(result.statusCode).toBe(200);
    });
  });
});
