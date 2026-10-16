/**
 * Type of OAuth2 access token.
 */
type TokenType = "Bearer" | "Mac";

/**
 * Standard OAuth2 token response.
 *
 * This struct includes the fields defined in
 * {@link https://tools.ietf.org/html/rfc6749#section-5.1|Section 5.1 of RFC 6749}, as well as
 * extensions defined by the `EF` type parameter.
 */
export type TokenResponse = {
  access_token: string;
  token_type: TokenType;
  expires_in?: number;
  refresh_token?: string;
  scopes: Array<string>;

  [key: string]: unknown;
}

