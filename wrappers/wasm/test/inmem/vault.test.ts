import { Credential, CredentialEntry, InMemVault } from "../../pkg";
import { VCFormat } from "../../types";
import { VC_TYPE } from "../vc/oid4vp/fixtures";

const SD_JWT_VC =
  "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~";
describe("InMemVault: ", () => {
  test("store, get and delete credential", async () => {
    const vault = new InMemVault();

    const sdJwt: Credential = {
      format: VCFormat.SdJwtVc,
      payload: SD_JWT_VC,
    };

    const sdJwtMetadata = {
      type: VC_TYPE,
      kid: "kid",
      format: VCFormat.SdJwtVc,
      fields: ["$.vct", "$.name"],
    };

    const cred_id = await vault.storeCredential(sdJwt, sdJwtMetadata);

    const credEntry: CredentialEntry = {
      credential: sdJwt,
      kid: sdJwtMetadata.kid,
      id: cred_id,
    };

    const credential = await vault.getCredential(cred_id);

    expect(credential).toEqual(credEntry);

    const credentials = await vault.getCredentials();

    expect(credentials).toEqual([credEntry]);

    const foundCredentials = await vault.findCredentials(["$.vct", "$.name"]);

    expect(foundCredentials).toEqual([credEntry]);

    await vault.deleteCredential(cred_id);

    const emptyCredentials = await vault.getCredentials();

    expect(emptyCredentials).toEqual([]);
  });
});
