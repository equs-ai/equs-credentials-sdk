# Conformance testing of Holder (Wallet)

## Testing Holder for Verifiable Presentations

Documentation for VP Holder
is [here](https://openid.net/certification/conformance-testing-for-openid-for-verifiable-presentations/)

### 1) Holder with Redirect Uri

- Test Plan -> OpenID for Verifiable Presentations ID2: Test a wallet - alpha tests (not currently part of certification
  program)
- Credential Format -> sd_jwt_vc
- Client Id Scheme -> redirect_uri
- Request Method -> request_uri_unsigned
- Response Mode -> direct_post

You run demo with cross-device flow and when holder asks for **presentation request uri** from url you insert value of
Browser Interaction's QR code's value:
![img.png](holder-vp-browser-interaction-qr-code.png)
That is only interaction in this test.

### 2) Holder with did

- Test Plan -> OpenID for Verifiable Presentations ID2: Test a wallet - alpha tests (not currently part of certification
  program)
- Credential Format -> sd_jwt_vc
- Client Id Scheme -> did
- Request Method -> request_uri_signed
- Response Mode -> direct_post

You run demo with cross-device flow and when holder asks for **presentation request uri** from url you insert value of
Browser Interaction's QR code's value:
![img.png](holder-vp-browser-interaction-qr-code.png)

In some of the cases it is required to upload screenshot of a browser with an error to finish test.