import { createUniversalDidResolver, DIDKey, KeyMetadata, KeyType, NativeKms } from "../../";

export type DidAndKeyMetadata = {
  did: string;
  keyMetadata: KeyMetadata;
};

export async function createDidAndKeyMetadata(kms: NativeKms): Promise<DidAndKeyMetadata> {
  const keyId = await kms.create(KeyType.P256);
  const keyHandle = await kms.get(keyId);
  const didKey = new DIDKey();
  const did = didKey.generate({
    alg: keyHandle.alg(),
    jwk: keyHandle.jwk() ?? undefined,
    pubKey: keyHandle.pubKey(),
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
