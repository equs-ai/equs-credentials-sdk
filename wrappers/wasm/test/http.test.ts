import { HttpClient, HttpMethod, HttpRequest } from "../pkg";

describe("HTTP Client: ", () => {
  jest.setTimeout(30000);
  let HTTP_URL = "http://httpbin.org/get";
  let HTTPS_URL = "https://httpbin.org/get";
  const HTTP_METHOD = HttpMethod.Get;
  const HEADERS = { Accept: "application/json" };

  describe("Secure mode: ", () => {
    test("should success with https url on secure mode", async () => {
      const client = new HttpClient();
      const request = new HttpRequest(HTTPS_URL, HTTP_METHOD, HEADERS, null);

      const result = await client.asyncCall(request);
      expect(result).toBeDefined();
      expect(result.statusCode).toBe(200);
    });

    test("should throw error with http url on secure mode", async () => {
      const client = new HttpClient();
      const request = new HttpRequest(HTTP_URL, HTTP_METHOD, HEADERS, null);

      await expect(client.asyncCall(request)).rejects.toThrow();
    });
  });

  describe("Secure mode: ", () => {
    test("should success with http url on insecure mode", async () => {
      const client = HttpClient.insecure();
      const request = new HttpRequest(HTTP_URL, HTTP_METHOD, HEADERS, null);

      const result = await client.asyncCall(request);
      expect(result).toBeDefined();
      expect(result.statusCode).toBe(200);
    });
  });
});
