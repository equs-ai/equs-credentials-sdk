import fs from "fs/promises";

(async () => {
  try {
    const externalTypesFilePath = "./dist";
    const internalTypesFilePath = "./types";
    const typesFile = "pkg/index.d.ts";
    const jsFile = "pkg/index.js";
    const encoding = "utf8";

    let typesContent = await fs.readFile(typesFile, encoding);
    let jsContent = await fs.readFile(jsFile, encoding);
    let exportTypesStr = `export * from \"${externalTypesFilePath}\";\n`;
    let exportDistStr = `export * from \"${internalTypesFilePath}\";\n`;
    let exportJsStr = `\nmodule.exports = require(\"${internalTypesFilePath}\");\n`;

    await fs.writeFile(typesFile, exportTypesStr + exportDistStr + typesContent, encoding);
    await fs.writeFile(jsFile, exportJsStr + jsContent, encoding);

    console.log(`Added import and export lines in ${typesFile}`);
  } catch (error) {
    console.error("Error occurred:", error);
  }
})();
