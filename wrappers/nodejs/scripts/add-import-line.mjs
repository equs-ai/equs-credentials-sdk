import fs from "fs/promises";

(async () => {
	try {
		const TYPES_FILE_PATH = "./types";
		let content = await fs.readFile("index.d.ts", "utf8");
		const exported_types = [
			"PresentationDefinition",
			"PresentationSubmission",
			"DIDDocument",
			"DIDResolution",
			"DIDVerificationMethod",
			"Claims",
			"CredentialOfferGrants",
			"AuthMetadata",
			"TokenResponse",
			"OID4VCICredentialRequest",
			"OID4VCICredentialMetadata",
			"OID4VCIIssuerMetadata",
			"OID4VCICredentialOffer",
			"ClientMetadata",
			"WalletMetadata",
		];
		let import_str = `import { ${exported_types.join(", ")} } from "${TYPES_FILE_PATH}";\nexport * from "${TYPES_FILE_PATH}";\n`;
		content = import_str + content;

		console.log(`Added import line in index.d.ts`);

		await fs.writeFile("index.d.ts", content, "utf8");
	} catch (error) {
		console.error("Error occurred:", error);
	}
})();
