import fs from "fs/promises";

(async () => {
  try {
    const TYPES_FILE_PATH = "@equstng/agent-sdk";
    let content = await fs.readFile("binary.d.ts", "utf8");
    const exported_types = [
      "Credential",
      "CredentialMetadata",
      "CredentialEntry",
    ];
    let import_str = `import { ${exported_types.join(", ")} } from "${TYPES_FILE_PATH}";\n`;
    content = import_str + content;

    await fs.writeFile("binary.d.ts", content, "utf8");
    console.log(`Added import line in binary.d.ts`);
  } catch (error) {
    console.error("Error occurred:", error);
  }
})();
