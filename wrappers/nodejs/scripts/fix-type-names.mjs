// TODO: Remove this script after the following bugs have been fixed: https://github.com/napi-rs/napi-rs/issues/1586, https://github.com/napi-rs/napi-rs/issues/1666
import fs from "fs/promises";

// JS types that are not renamed automatically should be added to this list.
const replacements = [
  { from: "JsAlg", to: "Alg" },
  { from: "JsVCFormat", to: "VCFormat" },
  { from: "JsKeyType", to: "KeyType" },
  { from: "JsCredential", to: "Credential" },
  { from: "JsCredentialOffer", to: "CredentialOffer" },
  { from: "JsCredentialRequest", to: "CredentialRequest" },
  { from: "JsCredentialOfferData", to: "CredentialOfferData" },
  { from: "JsCredentialMetadata", to: "CredentialMetadata" },
  { from: "JsCredentialEntry", to: "CredentialEntry" },
  { from: "JsAuthorizationResponse", to: "AuthorizationResponse" },
  { from: "JsPresentationSession", to: "PresentationSession" },
  { from: "JsKeyMetadata", to: "KeyMetadata" },
  { from: "JsDIDAndKeyMetadata", to: "DIDAndKeyMetadata" },
  { from: "JsAuthResponseOptions", to: "AuthResponseOptions" },
  { from: "JsNonceData", to: "NonceData" },
  { from: "JsIssuerMetadata", to: "IssuerMetadata" },
  { from: "JsHolderMetadata", to: "HolderMetadata" },
  { from: "JsKeyHandle", to: "KeyHandle" },
  { from: "JsPresentation", to: "Presentation" },
  { from: "JsPresentationInput", to: "PresentationInput" },
  { from: "JsCredentialStatusInfo", to: "CredentialStatusInfo" },
  { from: "JsVCStatusesData", to: "VCStatusesData" },
  { from: "JsVCStatus", to: "VCStatus" },
  { from: "JsStatusList", to: "StatusList" },
  { from: "JsStatusIssuerMetadata", to: "StatusIssuerMetadata" },
  { from: "JsStatusListFormat", to: "StatusListFormat" },
  { from: "JsonObject", to: "Record<string, any>" },
];

(async () => {
  try {
    let content = await fs.readFile("binary.d.ts", "utf8");

    for (const { from, to } of replacements) {
      const regex = new RegExp(`\\b${from}\\b`, "g"); // Match whole word only
      content = content.replace(regex, to);
      console.log(`Replaced "${from}" with "${to}" in binary.d.ts`);
    }

    await fs.writeFile("binary.d.ts", content, "utf8");
  } catch (error) {
    console.error("Error occurred:", error);
  }
})();
