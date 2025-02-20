type TokenType = "Bearer" | "Mac";

export type TokenResponse = {
  access_token: string;
  token_type: TokenType;
  expires_in?: number;
  refresh_token?: string;
  scopes: Array<string>;

  [key: string]: unknown;
}

