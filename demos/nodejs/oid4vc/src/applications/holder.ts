import {
  createDidAndKeyMetadata,
  CredentialDeferred,
  CredentialImmediate,
  CredentialResponse,
  enableLogs,
  inMemKms,
  inMemVault,
  IssuerDiscovery,
  NativeKms,
  NonceData,
  Oid4VciHolder,
  Oid4VciHolderBuilder,
  Oid4VpHolder,
  Oid4VpHolderBuilder,
  resolveMetadata,
} from "../../../../../wrappers/nodejs";
import { config } from "../components/config";
import { readFromCLI } from "../components/utils";

async function main(): Promise<void> {
  await enableLogs();

  const kms = inMemKms();
  const vault = inMemVault();

  const issuerDiscovery = IssuerDiscovery.fromUrl(config.issuerServerUrl);

  const oid4VciHolder = await new Oid4VciHolderBuilder(
    kms,
    vault,
    config.clientId,
    issuerDiscovery,
  ).build();
  const oid4VpHolder = await new Oid4VpHolderBuilder(
    kms,
    vault,
    config.clientId,
  ).build();

  await issuanceFlow(oid4VciHolder, kms);
  await presentationFlow(oid4VpHolder);

  console.log("End of e2e demo! Demo finished successfully!");
  console.log("You can find results on verifier side");
}

setImmediate(main);

async function issuanceFlow(
  holder: Oid4VciHolder,
  kms: NativeKms,
): Promise<void> {
  const tokenResp = await holder.authzCodeFlowWithScope(
    "SD_JWT_cred_scope",
    async (url: string) => await readFromCLI(`Get code from ${url}`),
  );

  const credentialResponse = await requestAndStoreCredential(
    holder,
    kms,
    "SD_JWT_cred_1",
    tokenResp.access_token,
    undefined,
  );
  await requestAndStoreCredential(
    holder,
    kms,
    "SD_JWT_cred_2",
    tokenResp.access_token,
    credentialResponse.nonceData,
  );
}

async function presentationFlow(holder: Oid4VpHolder): Promise<void> {
  const requestURI = await readFromCLI(
    `Please enter presentation request URI from http://${config.servers.verifier.host}:${config.servers.verifier.port}/request_uri`,
  );

  const authRequest = await holder.getAuthorizationRequest(requestURI);
  console.log("Auth request received: ");
  console.dir(authRequest, { depth: 5 });

  console.log("Holder sends authorization/presentation response to Verifier");
  await holder.presentCredentialsAuto(authRequest);
}

function isCredentialImmediate(
  credential: CredentialImmediate | CredentialDeferred,
): credential is CredentialImmediate {
  return Object.hasOwn(credential, "credential");
}

async function requestAndStoreCredential(
  holder: Oid4VciHolder,
  kms: NativeKms,
  credDefId: string,
  accessToken: string,
  nonceData: NonceData | undefined,
): Promise<CredentialResponse> {
  const { keyMetadata } = await createDidAndKeyMetadata(kms);

  const credentialResponse = await holder.requestCredential(
    accessToken,
    credDefId,
    nonceData,
    keyMetadata,
  );

  const credential = credentialResponse.data;

  if (!isCredentialImmediate(credential))
    throw new Error("Credential response is Deferred. Unexpected result!");

  const credentialMetadata = await resolveMetadata(
    credential.credential,
    keyMetadata,
  );

  await holder.storeCredential(credential.credential, credentialMetadata);
  return credentialResponse;
}
