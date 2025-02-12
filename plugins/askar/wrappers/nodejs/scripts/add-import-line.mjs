import fs from "fs/promises";
import {NativeVault} from "@equstng/agent-sdk";

(async () => {
  try {
    const TYPES_FILE_PATH = "@equstng/agent-sdk";
    let content = await fs.readFile("index.d.ts", "utf8");
    const exported_types = [
      "Credential",
      "CredentialMetadata",
      "CredentialEntry",
      "KeyHandle"
    ];
    let import_str = `import { ${exported_types.join(", ")} } from "${TYPES_FILE_PATH}";\n`;
    content = import_str + content;

    console.log(`Added import line in index.d.ts`);

    await fs.writeFile("index.d.ts", content, "utf8");
  } catch (error) {
    console.error("Error occurred:", error);
  }
})();
