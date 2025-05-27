import { HttpClient, HttpRequest, HttpResponse } from "../..";

class WrappedHttpClient {
  constructor(private readonly client: HttpClient) {
    this.asyncCall = this.asyncCall.bind(this);
  }

  async asyncCall(request: HttpRequest): Promise<HttpResponse> {
    return await this.client.asyncCall(request);
  }
}

export function contextEnsuredHttpClient(client: HttpClient): HttpClient {
  return new WrappedHttpClient(client);
}
