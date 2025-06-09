import Testing
import Foundation
import Swifter
@testable import Asdk

@Suite(.serialized) class VaultTests {
    private var credentialId = "cred:12345"
        private var criteria = ["$.vct", "$.name"]
        private var credentialEntries = [
            CredentialEntry(
                credential: Credential(
                    format: VcFormat.sdJwtVc,
                    payload: "eyJ0eXAiOiJ2YytzZC1qd3QiLCJhbGciOiJFUzI1NiIsImtpZCI6ImRpZDprZXk6ekRuYWV4ZWgzVDFDemlXV1NFZVdweXVUa1hxaVQ1aWtpQ3c1aVpRUkJ2NEhYdWV4NiN6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2In0.eyJfc2QiOlsiZkp1Ri1FNUMzTnhleU5UTnNMbm1DX1pnM2FNYkVwTGF1QV9aWVFnU1B3VSJdLCJ2Y3QiOiJodHRwczovL2NyZWRlbnRpYWxzLmV4YW1wbGUuY29tL2lkZW50aXR5X2NyZWRlbnRpYWwiLCJzdWIiOiJkaWQ6a2V5OnpEbmFlajlRYWRnZFpudTh1RFhaWGQ0NTQ1ZGZKQUV2bVY2bm43eGFZVXF6Y3JQdk0iLCJuYmYiOjE3Mjg4ODI2MTEsIl9zZF9hbGciOiJzaGEtMjU2IiwiaXNzIjoiZGlkOmtleTp6RG5hZXhlaDNUMUN6aVdXU0VlV3B5dVRrWHFpVDVpa2lDdzVpWlFSQnY0SFh1ZXg2IiwiaWF0IjoxNzI4ODgyNjExLCJleHAiOjE3NjA0MTg2MTEsImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJGaEFNdi1UWGcyZ1NlOGpqZkhVcWdkTzdfMjZlSG9tWVNweUxxQk05WlNZIiwieSI6IkFNelNtSXRoMHZCUTFmZjI4RlF6c1paSS1XckxZdXFxSFI4TF9HbHZrWXMifX19.usBLTsyl9fgJWPjJvbyJlpaDmfXZNRuxJCt9voME2VAAb0GhncwakNACMUdAqS9fMU5e9Y9p-KUsuOOXXVAlmg~WyI4elFmQkItS3FZSHVKcW5wVER2c1VRIiwgIm5hbWUiLCAiSm9obiJd~"
                ),
                kid: "kid",
                id: "cred:12345"
            )
        ]
        private var metadata = CredentialMetadata(
            type: "vc_type",
            format: VcFormat.sdJwtVc,
            kid: "kid",
            alg: nil,
            fields: ["$.vct", "$.name"]
        )


    @Test func getCredential() async throws {
        let vault = self.mockVault()
        let credential = try await vault.getCredential(id: self.credentialId)

        #expect(credentialEntries.first == credential)
    }
    
    @Test func getAbsentCredential() async throws {
        let vault = self.mockVault()
        let credential = try await vault.getCredential(id: "cred:56789")

        #expect(nil == credential)
    }
    
    @Test func getCredentials() async throws {
        let vault = self.mockVault()
        let credentials = try await vault.getCredentials(pagination: nil)

        #expect(self.credentialEntries == credentials)
    }
    
    @Test func findCredentials() async throws {
        let vault = self.mockVault()
        let credentials = try await vault.findCredentials(fields: self.criteria, pagination: nil)

        #expect(self.credentialEntries == credentials)
    }
    
    @Test func storeCredential() async throws {
        let vault = self.mockVault()
        let storedCredentialId = try await vault.storeCredential(credential: self.credentialEntries.first!.credential, metadata: self.metadata)

        #expect(self.credentialId == storedCredentialId)
    }
    
    @Test func deleteCredential() async throws {
        let vault = self.mockVault()
        try await vault.deleteCredential(id: self.credentialId)
    }
    
    private func mockVault() -> Asdk.Vault {
        return wrapVaultForTests(vault: MockVault(
            credentialId: self.credentialId,
            criteria: self.criteria,
            credentialEntries: self.credentialEntries,
            metadata: self.metadata
        ))
    }

}


final class MockVault : Asdk.Vault {
    
    private let credentialId: String
    private let criteria: Array<String>
    private let credentialEntries: Array<CredentialEntry>
    private let metadata: CredentialMetadata
    
    init(
        credentialId: String,
        criteria: Array<String>,
        credentialEntries: Array<CredentialEntry>,
        metadata: CredentialMetadata
    ) {
        self.credentialId = credentialId
        self.criteria = criteria
        self.credentialEntries = credentialEntries
        self.metadata = metadata
    }
    
    func storeCredential(credential: Asdk.Credential, metadata: Asdk.CredentialMetadata) async throws -> String {
        #expect(self.credentialEntries.first?.credential == credential)
        #expect(self.metadata == metadata)
        return self.credentialId
    }
    
    func deleteCredential(id: String) async throws {
        #expect(self.credentialId == id)
    }
    
    func getCredential(id: String) async throws -> Asdk.CredentialEntry? {
        if (id != self.credentialId || self.credentialEntries.isEmpty) {
            return nil
        }

        return self.credentialEntries.first
    }
    
    func getCredentials(pagination: Asdk.VaultPagination?) async throws -> [Asdk.CredentialEntry] {
        return self.credentialEntries
    }
    
    func findCredentials(fields: [String], pagination: Asdk.VaultPagination?) async throws -> [Asdk.CredentialEntry] {
        #expect(self.criteria == fields)

        return self.credentialEntries
    }
    
    
}
