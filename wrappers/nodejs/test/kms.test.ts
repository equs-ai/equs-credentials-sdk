import { Alg, KeyHandle, KeyHandleTestHelper, KeyType, Kms } from "../binary";

describe("KMS: ", () => {
  const publicKey = Array.from(
    Buffer.from("huX4QOwcvioB2N3njNOnTOtElUvf7KIQnm6NvdfK2bs4qWecmcxVAXxyCBYuzxSpVRG7ETk9mO3RjUzsFUtDCg", "base64"),
  );

  const jwk = JSON.stringify({
    crv: "P-256",
    kid: "618d228e-4767-4aa2-8683-c35c86d7025c",
    kty: "EC",
    x: "huX4QOwcvioB2N3njNOnTOtElUvf7KIQnm6NvdfK2bs",
    y: "4qWecmcxVAXxyCBYuzxSpVRG7ETk9mO3RjUzsFUtDCg",
  });

  const payload = Uint8Array.from(Buffer.from("cmF3X3Rlc3RfdmFsdWU=", "base64"));

  const signature = Uint8Array.from(Buffer.from("ZW5jcnlwdGVkX3Rlc3RfdmFsdWU=", "base64"));

  describe("KeyHandle: ", () => {
    test("get signing algorithm", async () => {
      const test_key_handle = new KeyHandleTestHelper(mockKeyHandle());

      expect(test_key_handle.alg).toEqual(Alg.ES256);
    });

    test("get public key", async () => {
      const test_key_handle = new KeyHandleTestHelper(mockKeyHandle());

      expect(test_key_handle.pubKey).toEqual(publicKey);
    });

    test("get jwk", async () => {
      const test_key_handle = new KeyHandleTestHelper(mockKeyHandle());

      expect(test_key_handle.jwk).toEqual(jwk);
    });

    test("sign", async () => {
      const test_key_handle = new KeyHandleTestHelper(mockKeyHandle());

      expect(await test_key_handle.sign(payload)).toEqual(signature);
    });

    test("verify", async () => {
      const test_key_handle = new KeyHandleTestHelper(mockKeyHandle());

      await test_key_handle.verify(payload, signature);
    });
  });

  test("create", async () => {
    const kid = await mockKms().create(KeyType.P256);

    expect(kid).toEqual("test_kid");
  });

  test("get by Key ID", async () => {
    const key_handle = await mockKms().get("test_kid");

    expect(key_handle.pubKey).toEqual(publicKey);
  });

  test("get by Public Key", async () => {
    const key_handle = await mockKms().getByPublicKey(publicKey);

    expect(key_handle.pubKey).toEqual(publicKey);
  });

  function mockKeyHandle() {
    return new MockKeyHandle(Alg.ES256, payload, signature, publicKey, jwk);
  }

  function mockKms() {
    return new MockKms(KeyType.P256, "test_kid", mockKeyHandle());
  }
});

class MockKeyHandle implements KeyHandle {
  constructor(
    public readonly alg: Alg,
    private readonly expected_payload: Uint8Array,
    private readonly expected_signature: Uint8Array,
    public readonly pubKey?: number[],
    public readonly jwk?: string,
  ) {
    this.sign = this.sign.bind(this);
    this.verify = this.verify.bind(this);
  }

  async sign(payload: Uint8Array): Promise<Uint8Array> {
    expect(payload).toEqual(this.expected_payload);

    return this.expected_signature;
  }

  async verify(data: Uint8Array, signature: Uint8Array): Promise<void> {
    expect(data).toEqual(this.expected_payload);
    expect(signature).toEqual(this.expected_signature);
  }
}

class MockKms implements Kms {
  constructor(
    private readonly expected_key_type: KeyType,
    private readonly kid: string,
    private readonly keyHandle: MockKeyHandle,
  ) {}

  async create(kt: KeyType): Promise<string> {
    expect(kt).toEqual(this.expected_key_type);

    return this.kid;
  }

  async get(kid: string): Promise<KeyHandle> {
    expect(kid).toEqual(this.kid);

    return this.keyHandle;
  }

  async getByPublicKey(pk: number[]): Promise<KeyHandle> {
    expect(pk).toEqual(this.keyHandle.pubKey);

    return this.keyHandle;
  }
}
