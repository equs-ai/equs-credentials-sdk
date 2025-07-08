import { forHttpRequestTest, HttpClient, HttpMethod, HttpRequest, HttpResponse } from "../";

describe("Http client: ", () => {
  it("async call", async () => {
    const response = {
      statusCode: 201,
      body: '{bodyKey: "bodyValue"}',
      // header keys go to all lowercase
      headers: { headerkey: "headerValue" },
    };
    const client: HttpClient = {
      asyncCall: async (request: HttpRequest): Promise<HttpResponse> => {
        return response;
      },
    };

    const result = await forHttpRequestTest(client, {
      body: undefined,
      headers: {},
      method: HttpMethod.GET,
      url: "http://test.example.com",
    });

    expect(result).toEqual(response);
  });
});
