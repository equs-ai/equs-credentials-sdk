import Testing
import Foundation
import Swifter
@testable import EqusSdk

@Suite(.serialized) class VaultTests {
    private var credentialId = "cred:12345"
        private var criteria = ["$.vct", "$.name"]
        private var credentialEntries = [
            CredentialEntry(
                credential: Credential(
                    format: VcFormat.sdJwtVc,
                    payload: Fixtures.identitySdJwt
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
        let credentials = try await vault.getCredentials(options: nil)

        #expect(self.credentialEntries == credentials)
    }

    @Test func findCredentials() async throws {
        let vault = self.mockVault()
        let credentials = try await vault.findCredentials(fields: self.criteria, options: nil)

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

    private func mockVault() -> EqusSdk.Vault {
        return wrapVaultForTests(vault: MockVault(
            credentialId: self.credentialId,
            criteria: self.criteria,
            credentialEntries: self.credentialEntries,
            metadata: self.metadata
        ))
    }

}


final class MockVault : EqusSdk.Vault {

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

    func storeCredential(credential: EqusSdk.Credential, metadata: EqusSdk.CredentialMetadata) async throws -> String {
        #expect(self.credentialEntries.first?.credential == credential)
        #expect(self.metadata == metadata)
        return self.credentialId
    }

    func deleteCredential(id: String) async throws {
        #expect(self.credentialId == id)
    }

    func getCredential(id: String) async throws -> EqusSdk.CredentialEntry? {
        if (id != self.credentialId || self.credentialEntries.isEmpty) {
            return nil
        }

        return self.credentialEntries.first
    }

    func getCredentials(options: EqusSdk.VaultFetchOptions?) async throws -> [EqusSdk.CredentialEntry] {
        return self.credentialEntries
    }

    func findCredentials(fields: [String], options: EqusSdk.VaultFetchOptions?) async throws -> [EqusSdk.CredentialEntry] {
        #expect(self.criteria == fields)

        return self.credentialEntries
    }


}
