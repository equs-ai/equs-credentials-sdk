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
  { from: "JsInnerAuthorizationResponse", to: "InnerAuthorizationResponse" },
  { from: "JsAuthorizationResponseObject", to: "AuthorizationResponseObject" },
  { from: "JsAuthorizationResponseType", to: "AuthorizationResponseType" },
  { from: "JsPresentationSession", to: "_PresentationSession" },
  { from: "JsKeyMetadata", to: "KeyMetadata" },
  { from: "JsDIDAndKeyMetadata", to: "DIDAndKeyMetadata" },
  { from: "JsAuthResponseOptions", to: "AuthResponseOptions" },
  { from: "JsTransactionDataResponse", to: "TransactionDataResponse" },
  { from: "JsPassAuthRequestObject", to: "PassAuthRequestObject" },
  { from: "JsPassAuthRequestObjectType", to: "PassAuthRequestObjectType" },
  { from: "JsAuthorizationRequestMetadata", to: "AuthorizationRequestMetadata" },
  { from: "JsCredentialVerificationMetadata", to: "CredentialVerificationMetadata" },
  { from: "JsIssuerMetadata", to: "IssuerMetadata" },
  { from: "JsHolderMetadata", to: "HolderMetadata" },
  { from: "JsHolderBinder", to: "HolderBinder" },
  { from: "JsKeyHandle", to: "KeyHandle" },
  { from: "JsPresentation", to: "Presentation" },
  { from: "JsPresentationResult", to: "PresentationResult" },
  { from: "JsPresentationInput", to: "PresentationInput" },
  { from: "JsPresentationRestrictionValue", to: "InternalPresentationRestrictionValue" },
  { from: "JsCredentialStatusInfo", to: "CredentialStatusInfo" },
  { from: "JsVCStatusesData", to: "VCStatusesData" },
  { from: "JsVCStatus", to: "VCStatus" },
  { from: "JsStatusList", to: "StatusList" },
  { from: "JsStatusIssuerMetadata", to: "StatusIssuerMetadata" },
  { from: "JsStatusListFormat", to: "StatusListFormat" },
  { from: "JsTokenValidation", to: "TokenValidation" },
  { from: "JsDuration", to: "Duration" },
  { from: "JsECDHESParams", to: "ECDHESParams" },
  { from: "JsECDH1PUParams", to: "ECDH1PUParams" },
  { from: "JsBIP32Params", to: "BIP32Params" },
  { from: "JsAuthorizationResponseMetadata", to: "AuthorizationResponseMetadata" },
  { from: "JsIdTokenMetadata", to: "IdTokenMetadata" },
  { from: "JsVaultPagination", to: "VaultPagination" },
  { from: "JsHttpMethodForAuth", to: "HttpMethodForAuth" },
  { from: "JsProofOfPossessionMetadata", to: "ProofOfPossessionMetadata" },
  { from: "JsProofOfPossessionNotBefore", to: "InnerProofOfPossessionNotBefore" },
  { from: "JsProofOfPossessionNotBeforeStrategy", to: "InnerProofOfPossessionNotBeforeStrategy" },
  { from: "JsCredentialExtraVerification", to: "CredentialExtraVerification" },
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
