export class Utils {
	readonly webVerificationMethod = {
		id: expect.stringContaining("did:web:"),
		type: "Ed25519VerificationKey2020",
		controller: expect.stringContaining("did:web:"),
		publicKeyJwk: {
			kty: "OKP",
			crv: "Ed25519",
			x: expect.any(String),
		},
	};
	readonly keyVerificationMethod = {
		id: expect.stringContaining("did:key:"),
		type: "Ed25519VerificationKey2018",
		controller: expect.stringContaining("did:key:"),
		publicKeyJwk: {
			kty: "OKP",
			crv: "Ed25519",
			x: expect.any(String),
		},
	};
	readonly webResolveResponse = {
		"@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security#Ed25519VerificationKey2020"],
		id: expect.stringContaining("did:web:"),
		verificationMethod: [this.webVerificationMethod],
	};
	readonly keyResolveResponse = {
		metadata: {},
		docMetadata: {},
		doc: {
			"@context": [
				"https://www.w3.org/ns/did/v1",
				{
					Ed25519VerificationKey2018: "https://w3id.org/security#Ed25519VerificationKey2018",
					publicKeyJwk: {
						"@id": "https://w3id.org/security#publicKeyJwk",
						"@type": "@json",
					},
				},
			],
			id: expect.stringContaining("did:key:"),
			verificationMethod: [this.keyVerificationMethod],
			authentication: [expect.stringContaining("did:key:")],
			assertionMethod: [expect.stringContaining("did:key:")],
		},
	};
}
