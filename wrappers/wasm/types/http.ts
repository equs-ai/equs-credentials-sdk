export const enum HttpMethod {
  GET = "GET",
  POST = "POST",
  PUT = "PUT",
  DELETE = "DELETE",
  HEAD = "HEAD",
  OPTIONS = "OPTIONS",
  CONNECT = "CONNECT",
  PATCH = "PATCH",
  TRACE = "TRACE",
}

export interface HttpRequest {
  url: string;
  method: HttpMethod;
  headers: Record<string, any>;
  body?: string;
}

export interface HttpResponse {
  statusCode: number;
  headers: Record<string, any>;
  body?: string;
}

export interface HttpClient {
  asyncCall(request: HttpRequest): Promise<HttpResponse>;
}
