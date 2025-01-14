import fs from "fs/promises";

(async () => {
	try {
		let content = await fs.readFile("index.d.ts", "utf8");
		const exported_types = [
			"PresentationDefinition",
			"PresentationSubmission",
			"DIDDocument",
			"Claims",
			"CredentialOfferGrants",
			"AuthMetadata",
			"TokenResponse",
			"OID4VCICredentialRequest",
			"OID4VCICredentialMetadata",
			"OID4VCIIssuerMetadata",
		];
		let import_str = `import { ${exported_types.join(", ")} } from "./custom-types/entrypoint";\n`;
		content = import_str + content;

		console.log(`Added import line in index.d.ts`);

		await fs.writeFile("index.d.ts", content, "utf8");
	} catch (error) {
		console.error("Error occurred:", error);
	}
})();
