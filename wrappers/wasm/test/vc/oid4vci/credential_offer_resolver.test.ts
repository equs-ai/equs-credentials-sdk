import {AUTH_SERVER_METADATA, CRED_OFFER_WITH_PRE_AUTH_GRANT} from "./fixtures";
import {getLocal} from "mockttp";
import {HttpClient, OID4VCICredentialOfferResolver} from "agent-sdk";

describe("OID4VCI Credential Offer resolver: ", () => {
  test("resolve offer by reference with pre-authorized code grant", async () => {
    const mockServer = getLocal();
    await mockServer.start(9000);

    await mockServer.forGet("/auth/.well-known/openid-configuration").thenJson(200, AUTH_SERVER_METADATA);
    await mockServer.forGet("/credential_offer").thenJson(200, CRED_OFFER_WITH_PRE_AUTH_GRANT);

    const resolver = OID4VCICredentialOfferResolver.withHttpClient(HttpClient.insecure());

    const resolvedOffer = await resolver.resolve(
      "openid-credential-offer://?credential_offer_uri=http://localhost:9000/credential_offer",
    );

    expect(resolvedOffer).toEqual(CRED_OFFER_WITH_PRE_AUTH_GRANT);

    await mockServer.stop();
  });

  test("resolve offer by value with pre-authorized code grant", async () => {
    const resolver = OID4VCICredentialOfferResolver.withHttpClient(HttpClient.insecure());

    const resolvedOffer = await resolver.resolve(
      "openid-credential-offer://?credential_offer={%22credential_issuer%22:%22http://localhost:9000%22,%22credential_configuration_ids%22:[%22IDENTITY_SD_JWT%22],%22grants%22:{%22urn:ietf:params:oauth:grant-type:pre-authorized_code%22:{%22pre-authorized_code%22:%22code%22,%22tx_code%22:null,%22interval%22:null,%22authorization_server%22:%22http://localhost:9000/auth%22}}}",
    );

    expect(resolvedOffer).toEqual(CRED_OFFER_WITH_PRE_AUTH_GRANT);
  });
});
