import { config } from "../components/config.ts";
import {
  createDidAndKeyMetadata,
  createInputContainer,
  readFromBrowserInput,
  removeContainer,
} from "../components/utils.ts";
import init, {
  CredentialDeferred,
  CredentialImmediate,
  CredentialResponse,
  ReqwestHttpClient,
  InMemKms,
  InMemVault,
  IssuerDiscovery,
  NonceData,
  OID4VCIHolder,
  OID4VCIHolderBuilder,
  OID4VPHolder,
  OID4VPHolderBuilder,
  resolveMetadata,
} from "@equstng/agent-sdk";

export async function start(): Promise<void> {
  console.log("=".repeat(100));

  await init();
  const kms = new InMemKms();
  const vault = new InMemVault();

  const issuerDiscovery = IssuerDiscovery.fromUrl(config.issuerServerUrl);
  const oid4VciHolder = await new OID4VCIHolderBuilder(kms, vault, config.clientId, issuerDiscovery)
    .withHttpClient(ReqwestHttpClient.insecure())
    .build();

  const oid4VpHolder = await new OID4VPHolderBuilder(kms, vault, config.clientId)
    .withHttpClient(ReqwestHttpClient.insecure())
    .build();

  await issuanceFlow(oid4VciHolder, kms);
  await presentationFlow(oid4VpHolder);

  console.log("End of e2e demo! Demo finished successfully!");
  console.log("You can find results on verifier side");
}

async function issuanceFlow(holder: OID4VCIHolder, kms: InMemKms): Promise<void> {
  const tokenResp = await holder.authzCodeFlowWithScope("SD_JWT_cred_scope", async (url: string) => {
    const { container, input, button } = await createInputContainer("Get authz code from:", url);
    const result = await readFromBrowserInput({ input, button });
    await removeContainer(container);
    return result;
  });

  const credentialResponse = await requestAndStoreCredential(
    holder,
    kms,
    "SD_JWT_cred_1",
    tokenResp.access_token,
    undefined,
  );
  await requestAndStoreCredential(holder, kms, "SD_JWT_cred_2", tokenResp.access_token, credentialResponse.nonceData);
}

async function presentationFlow(holder: OID4VPHolder): Promise<void> {
  const { container, input, button } = await createInputContainer(
    "Enter presentation request URI from: ",
    `http://${config.servers.verifier.host}:${config.servers.verifier.port}/request_uri`,
  );
  const requestURI = await readFromBrowserInput({ input, button });
  await removeContainer(container);

  const authRequest = await holder.getAuthorizationRequest(requestURI);
  console.log("Auth request received: ");
  console.dir(authRequest, { depth: 2 });

  console.log("Holder sends authorization/presentation response to Verifier");
  await holder.presentCredentialsAuto(authRequest);
}

function isCredentialImmediate(
  credential: CredentialImmediate | CredentialDeferred,
): credential is CredentialImmediate {
  return Object.hasOwn(credential, "credential");
}

async function requestAndStoreCredential(
  holder: OID4VCIHolder,
  kms: InMemKms,
  credDefId: string,
  accessToken: string,
  nonceData: NonceData | undefined,
): Promise<CredentialResponse> {
  const { keyMetadata } = await createDidAndKeyMetadata(kms);

  const credentialResponse = await holder.requestCredential(accessToken, credDefId, nonceData, keyMetadata);

  const credential = credentialResponse.data;

  if (!isCredentialImmediate(credential)) throw new Error("Credential response is Deferred. Unexpected result!");

  const credentialMetadata = await resolveMetadata(credential.credential, keyMetadata);

  await holder.storeCredential(credential.credential, credentialMetadata);
  return credentialResponse;
}
