import {
	CredentialSearchCriteria,
	inMemKms,
	inMemVault,
	IssuerDiscovery,
	Oid4VciHolderBuilder,
	VCFormat,
} from "../../index";
import {
	ACCESS_TOKEN,
	ACCESS_TOKEN_RESPONSE,
	AUTH_SERVER_METADATA,
	CODE_RESPONSE,
	CRED_DEF_ID,
	CRED_OFFER,
	CRED_RESPONSE,
	CRED_TYPE,
	ISSUER_METADATA,
	SCOPE,
	SD_JWT_CREDS,
} from "./fixtures";
import { getLocal } from "mockttp";
import { createDidAndKeyMetadata } from "../utils/utils";

describe("OID4VCI Holder: ", () => {
	const mockServer = getLocal();

	beforeEach(async () => {
		await mockServer.start(9000);
		await mockServer.forGet("/.well-known/openid-credential-issuer").thenJson(200, ISSUER_METADATA);
		await mockServer.forGet("/auth/.well-known/openid-configuration").thenJson(200, AUTH_SERVER_METADATA);
	});

	afterEach(async () => await mockServer.stop());

	test("retrieve Issuer Metadata", async () => {
		const vciHolder = await buildHolder();

		const issuerMetadata = vciHolder.getIssuerMetadata();

		expect(issuerMetadata).toMatchObject(ISSUER_METADATA);
	});

	test("authorize using auth code", async () => {
		await mockServer.forPost("/auth/par/request").thenJson(201, CODE_RESPONSE);
		await mockServer.forPost("/auth/token").thenJson(200, ACCESS_TOKEN_RESPONSE);

		const vciHolder = await buildHolder();

		const token_response = await vciHolder.authzCodeFlowWithScope(SCOPE, async (_) => "code");

		expect(token_response).toEqual(ACCESS_TOKEN_RESPONSE);
	});

	test("request Credential", async () => {
		await mockServer.forPost("/credential").thenJson(200, CRED_RESPONSE);

		const kms = inMemKms();
		const vciHolder = await buildHolder(kms);
		const nonce = {
			nonce: "KB50VOm9I-kPLT9mAACV8g",
			expiresIn: 86400,
			created: 1728732136,
		};
		const { keyMetadata } = await createDidAndKeyMetadata(kms);

		const cred_response = await vciHolder.requestCredential(ACCESS_TOKEN, CRED_DEF_ID, nonce, keyMetadata);

		expect(cred_response).toMatchObject({
			data: {
				credential: {
					format: VCFormat.SdJwtVc,
					payload: SD_JWT_CREDS,
				},
				notificationId: "1111",
			},
			nonceData: {
				nonce: "0GtZieAoAL_3Zafyn6TgCA",
				expiresIn: 86440,
			},
		});
	});

	test("store Credential", async () => {
		const vault = inMemVault();
		const vciHolder = await buildHolder(inMemKms(), vault);
		const credential = {
			format: VCFormat.SdJwtVc,
			payload: SD_JWT_CREDS,
		};
		const metadata = {
			type: CRED_TYPE,
			kid: "1234",
			format: VCFormat.SdJwtVc,
			tags: [],
		};

		await vciHolder.storeCredential(credential, metadata);

		const criteria = CredentialSearchCriteria.byTypeAndFormat(CRED_TYPE, "vc+sd-jwt");
		const credentialEntries = await vault.findCredentials(criteria);

		expect(credentialEntries).toEqual([{ credential, kid: "1234" }]);
	});
});

async function buildHolder(kms = inMemKms(), vault = inMemVault()) {
	return await new Oid4VciHolderBuilder(kms, vault, "client_id", IssuerDiscovery.fromOffer(CRED_OFFER)).build();
}
