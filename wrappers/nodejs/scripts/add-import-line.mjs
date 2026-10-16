import fs from "fs/promises";

(async () => {
  try {
    const TYPES_FILE_PATH = "./";
    let content = await fs.readFile("binary.d.ts", "utf8");
    const exported_types = [
      "ResolvedPresentationQuery",
      "PresentationSubmission",
      "DIDDocument",
      "DIDVerificationMethod",
      "Claims",
      "CredentialOfferGrants",
      "AuthMetadata",
      "TokenResponse",
      "OID4VCICredentialRequest",
      "OID4VCICredentialMetadata",
      "OID4VCIIssuerMetadata",
      "OID4VCICredentialOffer",
      "ClientMetadata",
      "WalletMetadata",
      "DIDCommMessage",
      "PackEncryptedOptions",
      "PackEncryptedMetadata",
      "PackSignedMetadata",
      "UnpackMetadata",
      "UnpackOptions",
      "Service",
      "ResolutionOptionsParameter",
      "TransactionDataItem",
      "VerifierInfoEntry",
      "DelegationRequest",
      "DelegationParams",
      "AuthorizationResponse",
      "PresentationResult",
      "UnsignedCredential",
    ];
    let import_str = `import { ${exported_types.join(", ")} } from "${TYPES_FILE_PATH}";\n`;
    content = import_str + content;

    console.log(`Added import line in binary.d.ts`);

    await fs.writeFile("binary.d.ts", content, "utf8");
  } catch (error) {
    console.error("Error occurred:", error);
  }
})();
