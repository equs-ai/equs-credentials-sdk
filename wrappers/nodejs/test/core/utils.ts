import {
	Alg,
	createDidAndKeyMetadata,
	CredentialOfferContentFormat,
	inMemKms,
	inMemVault,
	IssuerMetadata,
	PresentationInput,
	VCFormat,
} from "../../index";

export class Utils {
	readonly nonce = "KB50VOm9I-kPLT9mAACV8g";
	readonly verifierId = "Verifier-id";
	readonly scope = "SD_JWT_cred_sample";
	readonly kms = inMemKms();
	readonly vault = inMemVault();

	get claims() {
		return {
			name: "John",
			surname: "Doe",
			address: "221B Baker Street",
			date: "09/09/1989",
		};
	}

	get presentationInput(): PresentationInput {
		return {
			id: this.scope,
			type: "https://credentials.example.com/identity_credential",
			format: {
				"vc+sd-jwt": {
					"sd-jwt_alg_values": ["ES256", "ES384"],
					"kb-jwt_alg_values": ["ES256", "ES384"],
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
						path: ["$.surname"],
					},
				],
			},
		};
	}

	async getKeyMetadata() {
		return (await createDidAndKeyMetadata(this.kms)).keyMetadata;
	}

	async getCredentialOffer() {
		const keyMetadata = await this.getKeyMetadata();
		return {
			content: {
				format: CredentialOfferContentFormat.CredDef,
				payload: {
					cred_def_id: "",
					format: "SdJwtVc",
					claims: {},
					supported_proofs: undefined,
					supported_signing_algs: undefined,
					display: undefined,
					protocol_data: undefined,
					key_metadata: {
						did_url: keyMetadata.didUrl,
						kid: keyMetadata.kid,
					},
				},
			},
			credDefId: this.scope,
			credOfferId: undefined,
			issuerId: "https://issuer-backend.com",
			params: {},
			protocolData: undefined,
			url: "http://localhost:35001",
		};
	}

	async getIssuerMetadata(): Promise<IssuerMetadata> {
		return {
			issuerId: "https://issuer-backend.com",
			credDefs: [
				{
					credDefId: this.scope,
					format: VCFormat.SdJwtVc,
					claims: {},
					supportedProofs: { Jwt: ["ES256"] },
					supportedSigningAlgs: [Alg.ES256, Alg.EdDSA],
					display: undefined,
					protocolData: {
						SdJwt: {
							vct: "https://credentials.example.com/identity_credential",
							disclosures: ["$.name", "$.surname"],
							lifetime: undefined,
						},
					},
					keyMetadata: await this.getKeyMetadata(),
				},
			],
			protocolData: undefined,
		};
	}
}
