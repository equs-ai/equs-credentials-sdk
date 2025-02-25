import { Alg, contextEnsuredKms, createKeyMetadata, KeyHandle, KeyType, Kms } from "..";
import { JWK, JWS } from "node-jose";

describe("KMS: ", () => {
  test("generate Key Metadata using JS KMS", async () => {
    const kms = contextEnsuredKms(await mockKms());
    const key_metadata = await createKeyMetadata(kms);

    const expected_key_metadata = {
      didUrl:
        "did:key:zDnaeZWZ4fqhGst7r1X8uguF92M3CxjAjNQwS5eLAPJ1sGCZx#zDnaeZWZ4fqhGst7r1X8uguF92M3CxjAjNQwS5eLAPJ1sGCZx",
      kid: "test",
    };

    expect(key_metadata).toEqual(expected_key_metadata);
  });

  test("sign and verify", async () => {
    const kms = contextEnsuredKms(await mockKms());
    const keyHandle = await kms.get("test");

    const payload = new TextEncoder().encode("Secure payload");
    const signature = await keyHandle.sign(payload);
    await keyHandle.verify(payload, signature);

    return;
  });
});

class MockKms implements Kms {
  constructor(readonly _keyHandle: MockKeyHandle) {}

  async create(kt: KeyType): Promise<string> {
    return "test";
  }

  async get(kid: string): Promise<KeyHandle> {
    return this._keyHandle;
  }

  async getByPublicKey(pk: Array<number>): Promise<KeyHandle> {
    if (pk !== this._keyHandle.pubKey) throw new Error(`Key Handle Not found`);

    return this._keyHandle;
  }
}

class MockKeyHandle implements KeyHandle {
  constructor(
    readonly key: JWK.Key,
    readonly keyStore: JWK.KeyStore,
    readonly pubKey: number[],
    readonly jwk: string,
    readonly alg: Alg,
  ) {}

  async sign(payload: Uint8Array): Promise<Uint8Array> {
    const payloadBuffer = Buffer.from(payload);
    const signature = await JWS.createSign(
      {
        format: "compact",
        alg: "ES256",
      },
      this.key,
    )
      .update(payloadBuffer)
      .final();
    return new Uint8Array(Buffer.from(String(signature)));
  }

  async verify(data: Uint8Array, signature: Uint8Array): Promise<void> {
    const signatureStr = Buffer.from(signature).toString("utf8");
    const result = await JWS.createVerify(this.keyStore).verify(signatureStr);
    const payload = Buffer.from(result.payload).toString();
    const expected_payload = Buffer.from(data).toString("utf8");
    if (payload !== expected_payload) throw new Error(`Verification failed: Actual: ${payload}, Expected: ${data}`);
  }
}

async function mockKms() {
  const jwkWithPrivateKey = {
    kty: "EC",
    kid: "618d228e-4767-4aa2-8683-c35c86d7025c",
    crv: "P-256",
    x: "huX4QOwcvioB2N3njNOnTOtElUvf7KIQnm6NvdfK2bs",
    y: "4qWecmcxVAXxyCBYuzxSpVRG7ETk9mO3RjUzsFUtDCg",
    d: "hp8J4pfRBfqAeEOED4pnaOrztx1nc8X76npPjq6nF_c",
  };

  const keystore = JWK.createKeyStore();
  const key = await keystore.add(jwkWithPrivateKey, "json");

  const publicKeyBytes = Buffer.from(
    "huX4QOwcvioB2N3njNOnTOtElUvf7KIQnm6NvdfK2bs4qWecmcxVAXxyCBYuzxSpVRG7ETk9mO3RjUzsFUtDCg",
    "base64",
  );
  const publicKey = Array.from(publicKeyBytes);
  const jwk = JSON.stringify(key.toJSON());

  const keyHandle = new MockKeyHandle(key, keystore, publicKey, jwk, Alg.ES256);

  return new MockKms(keyHandle);
}
