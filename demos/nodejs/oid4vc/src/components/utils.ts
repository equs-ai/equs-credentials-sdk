import { createInterface } from "node:readline";
import {
  DIDKey,
  KeyMetadata,
  KeyType,
  Kms,
  UniversalDIDResolver,
} from "@equstng/agent-sdk";

export type DidAndKeyMetadata = {
  did: string;
  keyMetadata: KeyMetadata;
};

export async function readFromCLI(message: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question(`${message} : `, (name) => {
      resolve(name);
      rl.close();
    });
  });
}

export async function createDidAndKeyMetadata(
  kms: Kms,
): Promise<DidAndKeyMetadata> {
  const keyId = await kms.create(KeyType.P256);
  const keyHandle = await kms.get(keyId);

  const didKey = new DIDKey();
  const did = didKey.generate({
    alg: keyHandle.alg,
    jwk: keyHandle.jwk,
    pubKey: keyHandle.pubKey,
    sign: keyHandle.sign,
    verify: keyHandle.verify,
  });

  const universalDidResolver = new UniversalDIDResolver();

  const vm = await universalDidResolver.resolveVerificationMethod(did);

  const keyMetadata: KeyMetadata = {
    didUrl: vm.id,
    kid: keyId,
  };

  return { did, keyMetadata };
}
