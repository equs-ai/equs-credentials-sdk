import {
  AuthorizationRequest,
  CredentialDeferred,
  CredentialImmediate,
  CredentialResponse,
  enableLogs,
  IssuerDiscovery,
  Kms,
  Oid4VciHolder,
  OID4VCIHolderBuilder,
  Oid4VpHolder,
  OID4VPHolderBuilder,
  ReqwestHttpClient,
  resolveMetadata,
  TracingLogFormat,
  TracingLogLevel,
} from "@equstng/agent-sdk";
import { config } from "../components/config";
import { createDidAndKeyMetadata, readFromCLI } from "../components/utils";
import {
  AskarKms,
  AskarStorage,
  AskarStorageConfig,
  AskarVault,
  KeyMethod,
} from "@equstng/agent-sdk-askar-storage";

async function main(): Promise<void> {
  await enableLogs(TracingLogFormat.Full, TracingLogLevel.Info);

  const storageConfig = {
    dbUrl: "sqlite://:memory:",
    keyMethod: KeyMethod.DeriveKey,
    passKey: "test_key",
    profile: "test",
  } satisfies AskarStorageConfig;

  const storage = await AskarStorage.create(storageConfig, false);
  const kms = new AskarKms(storage);
  const vault = new AskarVault(storage);

  const issuerDiscovery = IssuerDiscovery.fromUrl(config.issuerServerUrl);

  const insecureHttpClient = ReqwestHttpClient.insecure();

  const oid4VciHolder = await new OID4VCIHolderBuilder(
    kms,
    vault,
    config.clientId,
    issuerDiscovery,
  )
    .withHttpClient(insecureHttpClient)
    .build();

  const oid4VpHolder = await new OID4VPHolderBuilder(
    kms,
    vault,
    config.clientId,
  )
    .withHttpClient(insecureHttpClient)
    .build();

  await issuanceFlow(oid4VciHolder, kms);
  await presentationFlow(oid4VpHolder);
}

setImmediate(main);

async function issuanceFlow(holder: Oid4VciHolder, kms: Kms): Promise<void> {
  const tokenResp = await holder.authzCodeFlowWithScope(
    "SD_JWT_cred_scope",
    async (url: string) => await readFromCLI(`Get code from ${url}`),
  );

  await requestAndStoreCredential(
    holder,
    kms,
    "SD_JWT_cred_1",
    tokenResp.access_token,
  );
  await requestAndStoreCredential(
    holder,
    kms,
    "SD_JWT_cred_2",
    tokenResp.access_token,
  );
}

async function presentationFlow(holder: Oid4VpHolder): Promise<void> {
  const requestURI = await readFromCLI(
    `Please enter presentation request URI from http://${config.servers.verifier.host}:${config.servers.verifier.port}/request_uri`,
  );

  const authRequest = await holder.getAuthorizationRequest(requestURI);
  console.log("Auth request received: ");
  console.dir(authRequest, { depth: 2 });

  const shouldDecline = await readFromCLI(
    "Do you want to decline authorization request? Insert 'yes' to decline",
  );

  if (["yes", "y"].includes(shouldDecline))
    return await declineFlow(holder, authRequest);

  return await presentFlow(holder, authRequest);
}

async function declineFlow(
  holder: Oid4VpHolder,
  authRequest: AuthorizationRequest,
): Promise<void> {
  console.log("Declining Authorization request");
  await holder.declineAuthorizationRequest(authRequest);
  console.log("End of e2e demo! Authorization request has been declined!");
  return;
}

async function presentFlow(
  holder: Oid4VpHolder,
  authRequest: AuthorizationRequest,
): Promise<void> {
  console.log("Holder sends authorization/presentation response to Verifier");
  await holder.presentCredentialsAuto(authRequest, {});

  console.log(
    "End of e2e demo! Demo finished successfully! You can find results on verifier application",
  );
}

function isCredentialImmediate(
  credential: CredentialImmediate | CredentialDeferred,
): credential is CredentialImmediate {
  return Object.hasOwn(credential, "credentials");
}

async function requestAndStoreCredential(
  holder: Oid4VciHolder,
  kms: Kms,
  credDefId: string,
  accessToken: string,
): Promise<CredentialResponse> {
  const { keyMetadata } = await createDidAndKeyMetadata(kms);

  const credentialResponse = await holder.requestCredential(
    accessToken,
    credDefId,
    [keyMetadata],
  );

  const credentialImmediate = credentialResponse.data;

  if (!isCredentialImmediate(credentialImmediate))
    throw new Error("Credential response is Deferred. Unexpected result!");

  const credential = credentialImmediate.credentials.pop()!;
  const credentialMetadata = await resolveMetadata(
    credential,
    keyMetadata,
  );

  await holder.storeCredential(credential, credentialMetadata);
  return credentialResponse;
}
