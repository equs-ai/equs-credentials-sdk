type TokenType = "Bearer" | "Mac";

interface Duration {
  secs: number;
  nanos: number;
}

type Nonce = string;

interface StandartTokenResponse<TT extends TokenType> {
  access_token: string;
  token_type: TT;
  expires_in?: number;
  refresh_token?: string;
  scopes: Array<string>;

  [key: string]: unknown;
}

export type TokenResponse = StandartTokenResponse<TokenType>;
