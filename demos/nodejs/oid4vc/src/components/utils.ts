import { createInterface } from "node:readline";
import {
  createUniversalDidResolver,
  DIDKey,
  KeyMetadata,
  KeyType,
  Kms,
  NativeKeyHandle,
  NativeKms,
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
  kms: NativeKms | Kms,
): Promise<DidAndKeyMetadata> {
  const keyId = await kms.create(KeyType.P256);
  const keyHandle = await kms.get(keyId);

  const isNativeKms = keyHandle instanceof NativeKeyHandle;

  const didKey = new DIDKey();
  const did = didKey.generate({
    alg: isNativeKms ? keyHandle.alg() : keyHandle.alg,
    jwk: (isNativeKms ? keyHandle.jwk() : keyHandle.jwk) ?? undefined,
    pubKey: isNativeKms ? keyHandle.pubKey() : keyHandle.pubKey,
    sign: keyHandle.sign,
    verify: keyHandle.verify,
  });

  const universalDidResolver = createUniversalDidResolver();

  const vm = await universalDidResolver.resolveVerificationMethod(did);

  const keyMetadata: KeyMetadata = {
    didUrl: vm.id,
    kid: keyId,
  };

  return { did, keyMetadata };
}
