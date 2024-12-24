import { createUniversalDidResolver, DIDKey, inMemKms, KeyHandle, KeyType } from "../../index";
import { Utils } from "./utils";

describe("DID: ", () => {
	const utils = new Utils();
	let did: string;
	let keyHandle: KeyHandle;

	beforeEach(async () => {
		const kms = inMemKms();
		const key = await kms.create(KeyType.Ed25519);
		const nativeKeyHandle = await kms.get(key);
		const didKey = new DIDKey();

		keyHandle = {
			alg: nativeKeyHandle.alg(),
			jwk: nativeKeyHandle.jwk(),
			pubKey: nativeKeyHandle.pubKey(),
			sign: nativeKeyHandle.sign,
			verify: nativeKeyHandle.verify,
		};

		did = didKey.generate(keyHandle);
	});

	test("Value", async () => {
		expect(did).toEqual(expect.stringContaining("did:key:"));
	});

	describe("Universal Resolver: ", () => {
		const resolver = createUniversalDidResolver();

		test("Resolve", async () => {
			const result = await resolver.resolve(did, { input: { accept: "test" } });
			expect(result).toEqual(expect.objectContaining(utils.keyResolveResponse));
		});
		test("Resolve verification method", async () => {
			const result = await resolver.resolveVerificationMethod(did);
			expect(result).toEqual(expect.objectContaining(utils.keyVerificationMethod));
		});
	});
});
