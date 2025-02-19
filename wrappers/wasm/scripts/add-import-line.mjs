import fs from "fs/promises";

(async () => {
	try {
		const typesFilePath = "./dist";
		const file = "pkg/binary.d.ts";
		const encoding = "utf8"

		let content = await fs.readFile(file, encoding);
		const exported_types = [
			"DIDVerificationMethod", "DIDResolution",
		];
		let import_str = `import { ${exported_types.join(", ")} } from "${typesFilePath}";\n`;
		content = import_str + content;

		console.log(`Added import line in ${file}`);

		await fs.writeFile(file, content, encoding);
	} catch (error) {
		console.error("Error occurred:", error);
	}
})();
