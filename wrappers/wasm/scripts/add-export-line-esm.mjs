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

    let export_types_str = `export * from "${externalTypesFilePath}";\n`;
    let export_dist_str = `export * from "${internalTypesFilePath}";\n`;

    await fs.writeFile(typesFile, export_types_str + export_dist_str + typesContent, encoding);
    await fs.writeFile(jsFile, export_types_str + export_dist_str + jsContent, encoding);

    console.log(`Added import line in ${typesFile}`);
  } catch (error) {
    console.error("Error occurred:", error);
  }
})();
