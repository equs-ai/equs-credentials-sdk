import { Utils } from "./fixtures";
import { getLocal } from "mockttp";
import { ReqwestHttpClient, OID4VCICredentialOfferResolver } from "equs-sdk";

describe("OID4VCI Credential Offer resolver: ", () => {
  const port = 9000;
  const utils = new Utils({ issuerUrlPort: port });

  it("resolve offer by reference with pre-authorized code grant", async () => {
    const mockServer = getLocal();
    await mockServer.start(port);

    await mockServer.forGet("/.well-known/oauth-authorization-server/auth").thenJson(200, utils.authServerMetadata);
    await mockServer.forGet("/credential_offer").thenJson(200, utils.credOfferWithPreAuthGrant);

    const resolver = OID4VCICredentialOfferResolver.withHttpClient(ReqwestHttpClient.insecure());

    const resolvedOffer = await resolver.resolve(
      "openid-credential-offer://?credential_offer_uri=http://localhost:9000/credential_offer",
    );

    expect(resolvedOffer).toEqual(utils.credOfferWithPreAuthGrant);

    await mockServer.stop();
  });

  it("resolve offer by value with pre-authorized code grant", async () => {
    const resolver = OID4VCICredentialOfferResolver.withHttpClient(ReqwestHttpClient.insecure());

    const resolvedOffer = await resolver.resolve(
      "openid-credential-offer://?credential_offer={%22credential_issuer%22:%22http://localhost:9000%22,%22credential_configuration_ids%22:[%22IDENTITY_SD_JWT%22],%22grants%22:{%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:{%22pre-authorized_code%22:%22code%22,%22tx_code%22:null,%22interval%22:null,%22authorization_server%22:%22http://localhost:9000/auth%22}},%22additional_field%22:%22additional_value%22}",
    );

    expect(resolvedOffer).toEqual(utils.credOfferWithPreAuthGrant);
  });

  it("fail to resolve offer with incorrect protocol", async () => {
    const resolver = OID4VCICredentialOfferResolver.withHttpClient(ReqwestHttpClient.insecure());
    try {
      await resolver.resolve(
        "closeid-credential-offer://?credential_offer={%22credential_issuer%22:%22http://localhost:9000%22,%22credential_configuration_ids%22:[%22IDENTITY_SD_JWT%22],%22grants%22:{%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:{%22pre-authorized_code%22:%22code%22,%22tx_code%22:null,%22interval%22:null,%22authorization_server%22:%22http://localhost:9000/auth%22}},%22additional_field%22:%22additional_value%22}",
      );
      fail("Should fail to resolve offer with incorrect protocol");
    } catch (error) {
      // expected to fail
    }
  });
});
