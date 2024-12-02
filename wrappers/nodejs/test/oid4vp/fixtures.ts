export const AUTH_REQUEST_JWT =
	"eyJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWVRdUMzWjhRaWNScXpMV1Rjc3l4eEdweExoR1AzWEFYN1g2QU1vU1VqMkViQiN6RG5hZVF1QzNaOFFpY1JxekxXVGNzeXh4R3B4TGhHUDNYQVg3WDZBTW9TVWoyRWJCIiwidHlwIjoiSldUIn0.eyJyZXNwb25zZV9tb2RlIjoiZGlyZWN0X3Bvc3QiLCJyZXNwb25zZV90eXBlIjoidnBfdG9rZW4iLCJub25jZSI6IjkwSWxkNFdhd09DR0ZnbGZDTVU1eXd1TkxYV1FFOGdsWmhTemZPd3RMUUkiLCJjbGllbnRfbWV0YWRhdGEiOnsidnBfZm9ybWF0cyI6eyJ2YytzZC1qd3QiOnsiYWxnIjpbIkVkRFNBIiwiRVMyNTYiXX19fSwiY2xpZW50X2lkIjoiZGlkOmtleTp6RG5hZVF1QzNaOFFpY1JxekxXVGNzeXh4R3B4TGhHUDNYQVg3WDZBTW9TVWoyRWJCIiwiY2xpZW50X2lkX3NjaGVtZSI6ImRpZCIsInByZXNlbnRhdGlvbl9kZWZpbml0aW9uIjp7ImlkIjoiMWI5ZDZiY2QtYmJmZC00YjJkLTliNWQtYWI4ZGZiYmQ0YmVkIiwiaW5wdXRfZGVzY3JpcHRvcnMiOlt7ImlkIjoiSWRlbnRpdHktMSIsImNvbnN0cmFpbnRzIjp7ImZpZWxkcyI6W3sicGF0aCI6WyIkLnZjdCJdLCJwcmVkaWNhdGUiOm51bGwsImZpbHRlciI6eyJ0eXBlIjoic3RyaW5nIiwiY29uc3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwifSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9LHsicGF0aCI6WyIkLm5hbWUiXSwicHJlZGljYXRlIjpudWxsLCJvcHRpb25hbCI6dHJ1ZSwiaW50ZW50X3RvX3JldGFpbiI6ZmFsc2V9XX0sIm5hbWUiOiJJZGVudGl0eSBWQyIsInB1cnBvc2UiOiJXZSB3YW50IGFuIGlkZW50aXR5IiwiZm9ybWF0Ijp7InZjK3NkLWp3dCI6eyJzZC1qd3RfYWxnX3ZhbHVlcyI6WyJFUzI1NiIsIkVkRFNBIl0sImtiLWp3dF9hbGdfdmFsdWVzIjpbIkVTMjU2IiwiRWREU0EiXX19fV19LCJyZXNwb25zZV91cmkiOiJodHRwOi8vbG9jYWxob3N0OjkwMDEvcmVzcG9uc2UifQ.4YnvxrmmsrjilN-dGnNryW9NVYbw73BzDU8vBeH7AkmPV1DTRX1TEFbju1MQ7fcIGSdsO65J_dQ2njCLEWWomA";

export const AUTH_REQUEST = {
	clientId: "did:key:zDnaeQuC3Z8QicRqzLWTcsyxxGpxLhGP3XAX7X6AMoSUj2EbB",
	presentationDefinition: {
		id: "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
		input_descriptors: [
			{
				id: "Identity-1",
				constraints: {
					fields: [
						{
							path: ["$.vct"],
							predicate: null,
							filter: {
								type: "string",
								const: "https://credentials.example.com/identity_credential",
							},
							intent_to_retain: false,
						},
						{
							path: ["$.name"],
							intent_to_retain: false,
							predicate: null,
							optional: true,
						},
					],
				},
				name: "Identity VC",
				purpose: "We want an identity",
				format: {
					"vc+sd-jwt": {
						"sd-jwt_alg_values": ["ES256", "EdDSA"],
						"kb-jwt_alg_values": ["ES256", "EdDSA"],
					},
				},
			},
		],
	},
	responseUri: "http://localhost:9001/response",
	responseMode: "direct_post",
	responseType: "vp_token",
	nonce: "90Ild4WawOCGFglfCMU5ywuNLXWQE8glZhSzfOwtLQI",
};

export const PRESENTATION_DEFINITION = {
	id: "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
	input_descriptors: [
		{
			id: "Identity-1",
			name: "Identity VC",
			purpose: "We want an identity",
			format: {
				"vc+sd-jwt": {
					"sd-jwt_alg_values": ["ES256", "EdDSA"],
					"kb-jwt_alg_values": ["ES256", "EdDSA"],
				},
			},
			constraints: {
				fields: [
					{
						path: ["$.vct"],
						filter: {
							type: "string",
							const: "https://credentials.example.com/identity_credential",
						},
					},
					{
						path: ["$.name"],
						optional: true,
					},
				],
			},
		},
	],
};

export const PRESENTATION_SUBMISSION = {
	id: "e18f2155-1235-43e9-8f0c-1f18cf72911a",
	definition_id: "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
	descriptor_map: [{ id: "Identity-1", format: "vc+sd-jwt", path: "$" }],
};

export const VC_TYPE = "https://credentials.example.com/identity_credential";

export const VC =
	"eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~";
export const VP =
	"eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~eyJ0eXAiOiJrYitqd3QiLCJhbGciOiJFUzI1NiJ9.eyJub25jZSI6Im4wTmNFIiwiYXVkIjoiZGlkOmtleTp6RG5hZWZRQVBGVlF0OXNmVTYzaHlxWWdQemEycERTWFNKclByQ0c1cGFUNWVhUUpiIiwic2RfaGFzaCI6Im45dkFaUU04ZFNZSWVlVnJCLVExSHJGaWppY2VvcXBXUXV4SjFFT1lQSjQiLCJpYXQiOjE3Mjg4ODI2MTF9.2SQRzj4_PDTxVqoWCWtPGGgOzDn2d7sk6e8okhdAzqLgtvF6hUuOqHqzPd2XIJEDPtP0gfeV6W2dMRx3hKdrDA";

export const CLAIMS = {
	"vp_token": {
		"Identity-1": {
			vct: "https://credentials.example.com/identity_credential",
			sub: "did:key:zDnaej9QadgdZnu8uDXZXd4545dfJAEvmV6nn7xaYUqzcrPvM",
			nbf: 1728882611,
			iss: "did:key:zDnaexeh3T1CziWWSEeWpyuTkXqiT5ikiCw5iZQRBv4HXuex6",
			iat: 1728882611,
			exp: 1760418611,
			cnf: {
				jwk: {
					kty: "EC",
					crv: "P-256",
					x: "FhAMv-TXg2gSe8jjfHUqgdO7_26eHomYSpyLqBM9ZSY",
					y: "AMzSmIth0vBQ1ff28FQzsZZI-WrLYuqqHR8L_GlvkYs",
				},
			},
			name: "John",
		},
	}
};
