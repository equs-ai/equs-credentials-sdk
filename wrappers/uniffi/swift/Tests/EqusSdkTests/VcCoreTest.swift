import Foundation
import Testing

@testable import EqusSdk

enum VcCoreFixtures {
    static let nonce = "KB50VOm9I-kPLT9mAACV8g"
    static let verifierId = "Verifier-id"
    static let scope = "SD_JWT_cred_sample"
    static let issuerId = "https://issuer-backend.com"
    static let statusListId = "test_status_list"
    static func statusListUrl(port: in_port_t) -> String { "http://localhost:\(port)/status_list" }
    static let vct = "https://credentials.example.com/identity_credential"

    static let claims: String = #"{"name":"John","surname":"Doe","address":"221B Baker Street","date":"09/09/1989"}"#

    static func credStatusInfo(port: in_port_t) -> CredentialStatusInfo {
        .tokenStatusList(idx: 1, uri: statusListUrl(port: port))
    }

    static func statusIssuerMetadata(keyMetadata: KeyMetadata, port: in_port_t) -> StatusIssuerMetadata {
        StatusIssuerMetadata(
            issuerId: "test",
            supportedStatusLists: [
                StatusListDefinition(
                    id: statusListId,
                    format: .statusListTokenJwt(
                        SlMetadata(
                            statusListUrl: statusListUrl(port: port),
                            statusesNr: 32,
                            statusSize: 2
                        )
                    ),
                    keyMetadata: keyMetadata
                )
            ]
        )
    }

    static func issuerMetadata(keyMetadata: KeyMetadata) -> IssuerMetadata {
        IssuerMetadata(
            issuerId: issuerId,
            credDefs: [
                CredentialDefinition(
                    credDefId: scope,
                    format: .sdJwtVc,
                    claims: [:],
                    supportedProofs: [SupportedProofEntry(format: .jwt, algs: [.es256])],
                    supportedSigningAlgs: [.es256, .edDsa],
                    display: nil,
                    protocolData: .sdJwt(
                        vct: vct,
                        disclosures: ["$.name", "$.surname"],
                        lifetime: 600
                    ),
                    keyMetadata: keyMetadata
                )
            ],
            protocolData: nil
        )
    }

    static func holderMetadata() -> HolderMetadata {
        let pop = ProofOfPossessionMetadataBuilder().withLifetime(lifetime: Int64(300)).build()
        return HolderMetadata(clientId: "wallet-dev", pop: pop)
    }

    static func presentationInput() -> PresentationInput {
        PresentationInput(
            id: scope,
            format: "dc+sd-jwt",
            restrictions: [
                PresentationRestriction(
                    fields: ["$.vct"],
                    value: .const(vct),
                    optional: false
                ),
                PresentationRestriction(
                    fields: ["$.surname"],
                    value: nil,
                    optional: false
                ),
            ]
        )
    }
}

@Suite(.serialized)
class VcCoreTests {
    let http: MockHttpRouter
    let port: in_port_t
    let kms: InMemKms
    let keyMetadata: KeyMetadata
    let statusListJwt: String

    init() async throws {
        self.http = MockHttpRouter()
        // No socket is bound; the router matches on path, so the port only has to
        // make the fixture URLs well-formed.
        self.port = 9000
        self.kms = InMemKms()
        let kvm = await createDidAndKeyMetadata(kms: kms)
        self.keyMetadata = kvm.keyMetadata

        let statusIssuer = try VcCoreStatusIssuer(
            kms: kms,
            metadata: VcCoreFixtures.statusIssuerMetadata(keyMetadata: keyMetadata, port: port)
        )
        let result = try await statusIssuer.issueStatusList(
            statusListId: VcCoreFixtures.statusListId,
            statuses: .statusListToken([StatusEntry(index: 1, status: 0)])
        )
        if case let .statusListTokenJwt(jwt) = result {
            self.statusListJwt = jwt
        } else {
            throw NSError(
                domain: "VcCoreTests", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "expected StatusListTokenJwt variant"]
            )
        }

        let cachedJwt = self.statusListJwt
        self.http["/status_list"] = { _ in
            MockHttpRouter.ok(cachedJwt, contentType: "application/statuslist+jwt")
        }
    }


    @Test func statusIssuerIssuesStatusList() async throws {
        let statusIssuer = try VcCoreStatusIssuer(
            kms: kms,
            metadata: VcCoreFixtures.statusIssuerMetadata(keyMetadata: keyMetadata, port: port)
        )
        let result = try await statusIssuer.issueStatusList(
            statusListId: VcCoreFixtures.statusListId,
            statuses: .statusListToken([StatusEntry(index: 1, status: 0)])
        )
        guard case let .statusListTokenJwt(jwt) = result else {
            throw NSError(domain: "VcCoreTests", code: 2, userInfo: [NSLocalizedDescriptionKey: "expected StatusListTokenJwt"])
        }
        #expect(!jwt.isEmpty)
    }

    @Test func statusIssuerBuilderProducesUsableInstance() async throws {
        let builder = Oid4vciStatusIssuerBuilder(
            kms: kms,
            metadata: VcCoreFixtures.statusIssuerMetadata(keyMetadata: keyMetadata, port: port)
        )
        let statusIssuer = try builder.build()
        let result = try await statusIssuer.issueStatusList(
            statusListId: VcCoreFixtures.statusListId,
            statuses: .statusListToken([StatusEntry(index: 2, status: 1)])
        )
        if case .statusListTokenJwt = result {
            // OK
        } else {
            throw NSError(domain: "VcCoreTests", code: 3, userInfo: [NSLocalizedDescriptionKey: "expected StatusListTokenJwt"])
        }
    }

    @Test func issuerOffersCredential() async throws {
        let resolver = try UniversalDidResolver(resolvers: nil)
        let issuer = try VcCoreIssuer(
            kms: kms,
            metadata: VcCoreFixtures.issuerMetadata(keyMetadata: keyMetadata),
            didResolver: resolver
        )
        let offer = try issuer.offerCredential(credDefId: VcCoreFixtures.scope, protocolData: nil)
        #expect(offer.issuerId == VcCoreFixtures.issuerId)
        #expect(offer.credDefId == VcCoreFixtures.scope)
    }

    @Test func holderRequestStoreAndVerifyCredential() async throws {
        let vault = InMemVault()
        let resolver = try UniversalDidResolver(resolvers: nil)
        let issuer = try VcCoreIssuer(
            kms: kms,
            metadata: VcCoreFixtures.issuerMetadata(keyMetadata: keyMetadata),
            didResolver: resolver
        )
        let holder = try VcCoreHolder(
            kms: kms,
            vault: vault,
            metadata: VcCoreFixtures.holderMetadata(),
            didResolver: resolver,
            httpClient: http
        )

        let offer = try issuer.offerCredential(credDefId: VcCoreFixtures.scope, protocolData: nil)
        let credentialRequest = try await holder.requestCredential(
            credentialOffer: offer,
            nonce: VcCoreFixtures.nonce,
            keyMetadata: keyMetadata
        )
        #expect(!credentialRequest.proof.proof.isEmpty)

        let credential = try await issuer.issueCredential(
            credentialRequest: credentialRequest,
            claims: VcCoreFixtures.claims,
            nonce: VcCoreFixtures.nonce,
            statusInfo: VcCoreFixtures.credStatusInfo(port: port)
        )
        try await holder.verifyCredential(credential: credential)

        let metadata = try await resolveMetadata(credential: credential, metadata: keyMetadata)
        let stored = try await holder.storeCredential(credential: credential, metadata: metadata)
        #expect(!stored.isEmpty)
    }

    @Test func holderFindsAndPresentsCredential() async throws {
        let vault = InMemVault()
        let resolver = try UniversalDidResolver(resolvers: nil)
        let issuer = try VcCoreIssuer(
            kms: kms,
            metadata: VcCoreFixtures.issuerMetadata(keyMetadata: keyMetadata),
            didResolver: resolver
        )
        let holder = try VcCoreHolder(
            kms: kms,
            vault: vault,
            metadata: VcCoreFixtures.holderMetadata(),
            didResolver: resolver,
            httpClient: http
        )

        let offer = try issuer.offerCredential(credDefId: VcCoreFixtures.scope, protocolData: nil)
        let credentialRequest = try await holder.requestCredential(
            credentialOffer: offer,
            nonce: VcCoreFixtures.nonce,
            keyMetadata: keyMetadata
        )
        let credential = try await issuer.issueCredential(
            credentialRequest: credentialRequest,
            claims: VcCoreFixtures.claims,
            nonce: VcCoreFixtures.nonce,
            statusInfo: VcCoreFixtures.credStatusInfo(port: port)
        )
        let metadata = try await resolveMetadata(credential: credential, metadata: keyMetadata)
        _ = try await holder.storeCredential(credential: credential, metadata: metadata)

        let findResult = try await holder.findVcsForPresentation(
            presentationInput: VcCoreFixtures.presentationInput()
        )
        guard case let .credentials(entries) = findResult.data else {
            throw NSError(
                domain: "VcCoreTests", code: 4,
                userInfo: [NSLocalizedDescriptionKey: "expected credentials, got \(findResult.data)"]
            )
        }
        #expect(!entries.isEmpty)

        let binder = HolderBinder(nonce: VcCoreFixtures.nonce, verifierId: VcCoreFixtures.verifierId, responseUri: nil)
        let presentation = try await holder.createPresentationAuto(
            holderBinder: binder,
            presentationInput: VcCoreFixtures.presentationInput()
        )
        guard case let .sdJwtVp(presentationPayload) = presentation else {
            throw NSError(domain: "VcCoreTests", code: 5, userInfo: [NSLocalizedDescriptionKey: "expected sdJwtVp presentation"])
        }
        #expect(!presentationPayload.isEmpty)

        let explicit = try await holder.createPresentation(
            holderBinder: binder,
            presentationInput: VcCoreFixtures.presentationInput(),
            credential: entries.first!
        )
        guard case let .sdJwtVp(explicitPayload) = explicit else {
            throw NSError(domain: "VcCoreTests", code: 6, userInfo: [NSLocalizedDescriptionKey: "expected sdJwtVp explicit presentation"])
        }
        #expect(!explicitPayload.isEmpty)
    }

    @Test func verifierVerifiesPresentation() async throws {
        let vault = InMemVault()
        let resolver = try UniversalDidResolver(resolvers: nil)
        let issuer = try VcCoreIssuer(
            kms: kms,
            metadata: VcCoreFixtures.issuerMetadata(keyMetadata: keyMetadata),
            didResolver: resolver
        )
        let holder = try VcCoreHolder(
            kms: kms,
            vault: vault,
            metadata: VcCoreFixtures.holderMetadata(),
            didResolver: resolver,
            httpClient: http
        )
        let verifier = try VcCoreVerifier(verifierId: VcCoreFixtures.verifierId, didResolver: resolver, httpClient: http)

        let offer = try issuer.offerCredential(credDefId: VcCoreFixtures.scope, protocolData: nil)
        let credentialRequest = try await holder.requestCredential(
            credentialOffer: offer,
            nonce: VcCoreFixtures.nonce,
            keyMetadata: keyMetadata
        )
        let credential = try await issuer.issueCredential(
            credentialRequest: credentialRequest,
            claims: VcCoreFixtures.claims,
            nonce: VcCoreFixtures.nonce,
            statusInfo: VcCoreFixtures.credStatusInfo(port: port)
        )
        let metadata = try await resolveMetadata(credential: credential, metadata: keyMetadata)
        _ = try await holder.storeCredential(credential: credential, metadata: metadata)

        let binder = HolderBinder(nonce: VcCoreFixtures.nonce, verifierId: VcCoreFixtures.verifierId, responseUri: nil)
        let presentation = try await holder.createPresentationAuto(
            holderBinder: binder,
            presentationInput: VcCoreFixtures.presentationInput()
        )

        let claimsJson = try await verifier.verifyPresentation(
            holderBinder: binder,
            presentation: presentation
        )
        #expect(claimsJson.contains("221B Baker Street"))
        #expect(claimsJson.contains(VcCoreFixtures.vct))
    }
}
