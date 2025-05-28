import fs from "fs/promises";

(async () => {
  try {
    const externalTypesFilePath = "./dist";
    const internalTypesFilePath = "./types";
    const typesFile = "pkg/index.d.ts";
    const jsFile = "pkg/index.js";
    const encoding = "utf8";

    const typesContent = await fs.readFile(typesFile, encoding);
    const jsContent = await fs.readFile(jsFile, encoding);
    const exportTypesStr = `export * from \"${externalTypesFilePath}\";\n`;
    const exportDistStr = `export * from \"${internalTypesFilePath}\";\n`;
    const exportTypesJsStr = `\nconst internalTypes = require(\"${internalTypesFilePath}\");\n`;
    const exportDistJsStr = `\nconst externalTypes = require(\"${externalTypesFilePath}\");\n`;
    const exportJsStr = `module.exports = {...internalTypes, ...externalTypes};\n`;

    await fs.writeFile(typesFile, exportTypesStr + exportDistStr + typesContent, encoding);
    await fs.writeFile(jsFile, exportTypesJsStr + exportDistJsStr + exportJsStr + jsContent, encoding);

    console.log(`Added import and export lines in ${typesFile}`);
  } catch (error) {
    console.error("Error occurred:", error);
  }
})();
