import { ReqwestHttpClient, HttpMethod, HttpRequest } from "agent-sdk";

describe("HTTP Client: ", () => {
  jest.setTimeout(30000);
  const HTTP_URL = "http://httpbin.org/get";
  const HTTPS_URL = "https://httpbin.org/get";
  const HTTP_METHOD = HttpMethod.GET;
  const HEADERS = { Accept: "application/json" };

  describe("Secure mode: ", () => {
    test("should success with https url on secure mode", async () => {
      const client = new ReqwestHttpClient();
      const request: HttpRequest = { url: HTTPS_URL, method: HTTP_METHOD, headers: HEADERS, body: undefined };

      const result = await client.asyncCall(request);
      expect(result).toBeDefined();
      expect(result.statusCode).toBe(200);
    });

    test("should throw error with http url on secure mode", async () => {
      const client = new ReqwestHttpClient();
      const request: HttpRequest = { url: HTTP_URL, method: HTTP_METHOD, headers: HEADERS, body: undefined };

      await expect(client.asyncCall(request)).rejects.toThrow();
    });
  });

  describe("Insecure mode: ", () => {
    test("should success with http url on insecure mode", async () => {
      const client = ReqwestHttpClient.insecure();
      const request: HttpRequest = { url: HTTPS_URL, method: HTTP_METHOD, headers: HEADERS, body: undefined };

      const result = await client.asyncCall(request);
      expect(result).toBeDefined();
      expect(result.statusCode).toBe(200);
    });
  });
});
