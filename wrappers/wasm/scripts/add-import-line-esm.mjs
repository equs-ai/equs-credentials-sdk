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

    const importedExternalTypes = [
      "DIDVerificationMethod",
      "OID4VCIIssuerMetadata",
      "OID4VCICredentialOffer",
      "TokenResponse",
      "DIDDocument",
      "WalletMetadata",
      "Claims",
      "AuthorizationRequest",
      "CommonAuthorizationRequest",
    ];
    const importedInternalTypes = [
      "DIDResolution",
      "Alg",
      "AuthorizationResponseMetadata",
      "Credential",
      "CredentialEntry",
      "CredentialResponse",
      "CredentialMapping",
      "CredentialsMapping",
      "CredentialMetadata",
      "DIDResolver",
      "KeyHandle",
      "KeyMetadata",
      "KeyType",
      "Kms",
      "NonceData",
      "VerificationRelationshipType",
      "VaultPagination",
      "Vault",
      "HttpRequest",
    ];

    const importedExternalValues = ["AuthorizationRequest"];

    const importExternalTypesStr = `import { ${importedExternalTypes.join(", ")} } from "${externalTypesFilePath}";\n`;
    const importInternalTypesStr = `import { ${importedInternalTypes.join(", ")} } from "${internalTypesFilePath}";\n`;

    const importedExternalValuesStr = `import { ${importedExternalValues.join(", ")} } from "${externalTypesFilePath}";\n`;

    await fs.writeFile(typesFile, importExternalTypesStr + importInternalTypesStr + typesContent, encoding);
    await fs.writeFile(jsFile, importedExternalValuesStr + jsContent, encoding);

    console.log(`Added import line in ${typesFile}`);
  } catch (error) {
    console.error("Error occurred:", error);
  }
})();
