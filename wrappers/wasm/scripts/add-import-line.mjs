import fs from "fs/promises";

(async () => {
  try {
    const externalTypesFilePath = "./dist";
    const internalTypesFilePath = "./types";
    const file = "pkg/binary.d.ts";
    const encoding = "utf8"

    let content = await fs.readFile(file, encoding);
    const exported_external_types = [
      "DIDVerificationMethod",
      "OID4VCIIssuerMetadata",
      "OID4VCICredentialOffer",
      "TokenResponse",
      "DIDDocument",
      "WalletMetadata"
    ];
    const exported_internal_types = [
      "Alg",
      "AuthorizationRequest",
      "Credential",
      "CredentialEntry",
      "CredentialResponse",
      "CredentialMapping",
      "CredentialsMapping",
      "CredentialMetadata",
      "DIDResolution",
      "KeyMetadata",
      "KeyType",
      "NonceData",
      "VerificationRelationshipType"
    ];
    let import_external_str = `import { ${exported_external_types.join(", ")} } from "${externalTypesFilePath}";\n`;
    let import_internal_str = `import { ${exported_internal_types.join(", ")} } from "${internalTypesFilePath}";\n`;

    content = import_external_str + import_internal_str + content;

    console.log(`Added import line in ${file}`);

    await fs.writeFile(file, content, encoding);
  } catch (error) {
    console.error("Error occurred:", error);
  }
})();
