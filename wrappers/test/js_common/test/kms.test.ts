import { Alg, KeyType, KeyHandle, KeyHandleTestHelper, Kms, KmsTestHelper } from "equs-sdk";

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
    it("get signing algorithm", async () => {
      const test_key_handle = new KeyHandleTestHelper(mockKeyHandle());

      expect(test_key_handle.alg).toEqual(Alg.ES256);
    });

    it("get public key", async () => {
      const test_key_handle = new KeyHandleTestHelper(mockKeyHandle());

      expect(Array.from(test_key_handle.pubKey)).toEqual(publicKey);
    });

    it("get jwk", async () => {
      const test_key_handle = new KeyHandleTestHelper(mockKeyHandle());

      expect(JSON.parse(test_key_handle.jwk)).toMatchObject(JSON.parse(jwk));
    });

    it("sign", async () => {
      const test_key_handle = new KeyHandleTestHelper(mockKeyHandle());

      expect(await test_key_handle.sign(payload)).toEqual(signature);
    });

    it("verify", async () => {
      const test_key_handle = new KeyHandleTestHelper(mockKeyHandle());

      await test_key_handle.verify(payload, signature);
    });
  });

  it("create", async () => {
    const kid = await new KmsTestHelper(mockKms()).create(KeyType.P256);

    expect(kid).toEqual("test_kid");
  });

  it("get by Key ID", async () => {
    const key_handle = await new KmsTestHelper(mockKms()).get("test_kid");

    expect(Array.from(key_handle.pubKey)).toEqual(publicKey);
  });

  it("get by Public Key", async () => {
    const key_handle = await new KmsTestHelper(mockKms()).getByPublicKey(Uint8Array.from(publicKey));

    expect(Array.from(key_handle.pubKey)).toEqual(publicKey);
  });

  function mockKeyHandle() {
    return new MockKeyHandle(Alg.ES256, payload, signature, publicKey, jwk);
  }

  function mockKms() {
    return new MockKms(KeyType.P256, "test_kid", mockKeyHandle());
  }
});

class MockKeyHandle implements KeyHandle {
  readonly pubKey: KeyHandle["pubKey"];

  constructor(
    readonly alg: Alg,
    private readonly expected_payload: Uint8Array,
    private readonly expected_signature: Uint8Array,
    pubKey?: number[] | Uint8Array,
    readonly jwk?: string,
  ) {
    this.pubKey = pubKey as KeyHandle["pubKey"];
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
    private readonly expectedKeyType: KeyType,
    private readonly kid: string,
    private readonly keyHandle: MockKeyHandle,
  ) {
    this.create = this.create.bind(this);
    this.get = this.get.bind(this);
    this.getByPublicKey = this.getByPublicKey.bind(this);
  }

  async create(kt: KeyType): Promise<string> {
    expect(kt).toEqual(this.expectedKeyType);

    return this.kid;
  }

  async get(kid: string): Promise<KeyHandle> {
    expect(kid).toEqual(this.kid);

    return this.keyHandle;
  }

  async getByPublicKey(pk: Uint8Array): Promise<KeyHandle> {
    expect(pk).toEqual(Uint8Array.from(this.keyHandle.pubKey));

    return this.keyHandle;
  }
}
