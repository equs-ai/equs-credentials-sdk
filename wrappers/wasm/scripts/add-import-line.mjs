import fs from "fs/promises";

(async () => {
  try {
    const externalTypesFilePath = "./dist";
    const internalTypesFilePath = "./types";
    const typesFile = "pkg/index.d.ts";
    const encoding = "utf8";

    let typesContent = await fs.readFile(typesFile, encoding);
    const exported_external_types = [
      "DIDVerificationMethod",
      "OID4VCIIssuerMetadata",
      "OID4VCICredentialOffer",
      "TokenResponse",
      "DIDDocument",
      "WalletMetadata",
      "Claims",
    ];
    const exported_internal_types = [
      "DIDResolution",
      "Alg",
      "AuthorizationRequest",
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
    let import_external_str = `import { ${exported_external_types.join(", ")} } from "${externalTypesFilePath}";\n`;
    let import_internal_str = `import { ${exported_internal_types.join(", ")} } from "${internalTypesFilePath}";\n`;

    await fs.writeFile(typesFile, import_external_str + import_internal_str + typesContent, encoding);

    console.log(`Added import line in ${typesFile}`);
  } catch (error) {
    console.error("Error occurred:", error);
  }
})();
