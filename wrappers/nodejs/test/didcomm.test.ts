import {
  DIDCommMessage,
  DIDCommService,
  DIDPeer,
  inMemKms,
  KeyType, NativeKms,
  VerificationRelationshipType
} from "../index";

describe("DIDComm: ", () => {
  test("pack encrypted", async () => {
    const senderKms = inMemKms()
    const recipientKms = inMemKms()

    const senderDid = await generate_did_peer(senderKms)
    const recipientDid = await generate_did_peer(recipientKms)

    const senderDIDCommService = new DIDCommService(senderKms);
    const recipientDIDCommService = new DIDCommService(recipientKms);

    const message: DIDCommMessage = {
      id: '123456',
      typ: 'application/didcomm-plain+json',
      type: 'DIDComm',
      from: senderDid,
      to: [recipientDid],
      body: 'Example Body',
    }

    const packResult = await senderDIDCommService.packEncrypted(message, recipientDid, senderDid);

    const unpackResult = await recipientDIDCommService.unpack(packResult.encryptedMsg)


    expect(unpackResult.metadata.encrypted).toBe(true)
    expect(unpackResult.metadata.authenticated).toBe(true)
    expect(unpackResult.message).toEqual(message)
  });

  test("pack signed", async () => {
    const senderKms = inMemKms()
    const senderDid = await generate_did_peer(senderKms)

    const senderDIDCommService = new DIDCommService(senderKms);
    const recipientDIDCommService = new DIDCommService(inMemKms());

    const message: DIDCommMessage = {
      id: '123456',
      typ: 'application/didcomm-plain+json',
      type: 'DIDComm',
      body: 'Example Body',
    }

    const packResult = await senderDIDCommService.packSigned(message, senderDid);

    const unpackResult = await recipientDIDCommService.unpack(packResult.signedMsg)

    expect(unpackResult.message).toEqual(message)
  });

  test("pack plaintext", async () => {
    const didCommService = new DIDCommService(inMemKms());

    const message: DIDCommMessage = {
      id: '123456',
      typ: 'application/didcomm-plain+json',
      type: 'DIDComm',
      body: 'Example Body',
    }

    const packResult = await didCommService.packPlaintext(message);


    expect(packResult).toEqual('{"id":"123456","typ":"application/didcomm-plain+json","type":"DIDComm","body":"Example Body"}')
  });
});

async function generate_did_peer(kms: NativeKms): Promise<string> {
  const kid = await kms.create(KeyType.P256)
  const keyHandle = await kms.get(kid)

  return DIDPeer.generateDidPeer4([{
      key: {
        alg: keyHandle.alg(),
        jwk: keyHandle.jwk() ?? undefined,
        pubKey: keyHandle.pubKey(),
        sign: keyHandle.sign,
        verify: keyHandle.verify,
      },
      verificationRelationships: [
        VerificationRelationshipType.Authentication,
        VerificationRelationshipType.Assertion,
        VerificationRelationshipType.KeyAgreement
      ]
    }],
    []
  )
}