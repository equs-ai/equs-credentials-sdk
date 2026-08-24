import { ReqwestHttpClient, OID4VCICredentialOfferResolver, CredentialOfferResolverError, EqusSdkError } from "../../";

describe("OID4VCI Credential Offer resolver: ", () => {
  it("fail to resolve incorrect protocol offer with json-encoded error", async () => {
    const resolver = OID4VCICredentialOfferResolver.withHttpClient(ReqwestHttpClient.insecure());
    try {
      await resolver.resolve(
        "closeid-credential-offer://?credential_offer={%22credential_issuer%22:%22http://localhost:9000%22,%22credential_configuration_ids%22:[%22IDENTITY_SD_JWT%22],%22grants%22:{%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:{%22pre-authorized_code%22:%22code%22,%22tx_code%22:null,%22interval%22:null,%22authorization_server%22:%22http://localhost:9000/auth%22}}}",
      );
      fail("Should fail to resolve offer with incorrect protocol");
    } catch (error) {
      let parsed_error: EqusSdkError = JSON.parse(error.message);
      expect(parsed_error.code).toEqual(CredentialOfferResolverError.Resolve);
      expect(parsed_error.message).toEqual("Offer resolution error");
    }
  });
});
