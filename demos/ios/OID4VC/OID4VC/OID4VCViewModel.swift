//
//  ViewModels.swift
//  OID4VC
//
//  Created by Aziz Karabashov on 04/04/25.
//

import Foundation
import EqusSdk

enum ValueState<T> {
    case initial , loading , ready (data: T) , error (String)
}

@MainActor final class OID4VCViewModel: ObservableObject, AuthCodeCallback {

    @Published var initialization: ValueState<Void> = .initial

    @Published var authorizationCodeURL: ValueState<String> = .initial
    @Published var authCode: String = ""
    @Published var tokenResponse: ValueState<TokenResponse> = .initial

    @Published var credential: ValueState<String> = .initial

    @Published var requestUri: String = ""
    @Published var presentation: ValueState<Void> = .initial

    private var oid4vciHolder: Oid4vciHolder!
    private var oid4vpHolder: Oid4vpHolder!
    private var kms: InMemKms!
    private var vault: InMemVault!

    private var authCodeContinuation: CheckedContinuation<String, any Swift.Error>?

    @MainActor func setup() async {
        initialization = .loading

        kms = InMemKms()
        vault = InMemVault()

        do {
            self.oid4vciHolder = try await OID4VCViewModel.buildOid4vciHolder(
                kms: kms, vault: vault)
            self.oid4vpHolder = try await OID4VCViewModel.buildOid4vpHolder(kms: kms, vault: vault)

            self.initialization = .ready(data: ())
        } catch {
            print("error = \(error)")
            self.initialization = .error(error.localizedDescription)
        }
    }

    @MainActor func startAuthorizationFlow() async {
        authorizationCodeURL = .loading

        do {
            let tokenResponse = try await self.oid4vciHolder.authzCodeFlowWithScope(
                scope: Constants.scope, authorizationCodeCallback: self)
            self.tokenResponse = .ready(data: tokenResponse)
        } catch {
            print("error = \(error)")
            self.tokenResponse = .error("Auth code flow failed: \(error)")
        }
    }

    @MainActor func authenticate(url: String) async throws -> String {
        self.authorizationCodeURL = .ready(data: url)

        do {
            return try await withCheckedThrowingContinuation {
                continuation in
                self.authCodeContinuation = continuation
            }
        } catch {
            print("error = \(error)")
            throw Error.Oid4vciInternal("Auth code request failed: \(error)")
        }
    }

    func submitCode() {
        tokenResponse = .loading

        self.authCodeContinuation?.resume(returning: self.authCode)
        self.authCodeContinuation = nil
    }

    @MainActor func startCredentialIssuanceFlow(token: String) async {
        credential = .loading

        do {
            let didAndKeyMetadata = await createDidAndKeyMetadata(kms: kms)

            let credentialResponse = try await self.oid4vciHolder.requestCredential(
                token: token, credDefId: Constants.sdJwtCredDefId,
                keyMetadata: [didAndKeyMetadata.keyMetadata])

            switch credentialResponse.data {
            case .deferred(transactionId: _):
                self.credential = .error("Request for credential is deferred")
            case .immediate(credentials: let credentials, notificationId: _):
                let credential = credentials[0]
                self.credential = .ready(data: credential.payload)

                let metadata = try await resolveMetadata(
                    credential: credential, metadata: didAndKeyMetadata.keyMetadata)

                let _ = try await self.oid4vciHolder.storeCredential(
                    credential: credential, credentialMetadata: metadata)
            }
        } catch {
            print("error = \(error)")
            self.credential = .error("Credential issuance failed: \(error)")

        }
    }

    func restartIssuance() {
        credential = .initial
        tokenResponse = .initial
        authorizationCodeURL = .initial
        authCode = ""
    }

    @MainActor func startPresentationFlow() async {
        presentation = .loading

        do {
            let authorizationRequest = try await self.oid4vpHolder.getAuthorizationRequest(
                requestUri: requestUri)

            let didAndKeyMetadata = await createDidAndKeyMetadata(kms: kms)
            let idTokenMetadata = IdTokenMetadata(
                keyMetadata: didAndKeyMetadata.keyMetadata, lifetime: 5)

            let _ = try await self.oid4vpHolder.presentCredentialsAuto(
                authRequest: authorizationRequest,
                authResponseMetadata: AuthorizationResponseMetadata(
                    claimsToExclude: nil, idTokenMetadata: idTokenMetadata, dcApiOrigin: nil))

            presentation = .ready(data: ())
        } catch {
            print("error = \(error)")
            self.presentation = .error("Presentation failed: \(error)")

        }
    }

    func restartPresentation() {
        requestUri = ""
        presentation = .initial
    }

    private static func buildOid4vciHolder(kms: InMemKms, vault: InMemVault) async throws -> Oid4vciHolder
        {
        try await Oid4vciHolderBuilder(
            kms: kms,
            vault: vault,
            clientId: Constants.clientId,
            issuerDiscovery: IssuerDiscovery.url(Constants.issuerUrl),
            httpClient: ReqwestHttpClient.insecure(),
            pop: ProofOfPossessionMetadata(lifetime: 3600, notBefore: nil),
            credentialExtraVerification: nil
        ).build()
    }

    private static func buildOid4vpHolder(kms: InMemKms, vault: InMemVault) async throws -> Oid4vpHolder
        {
        try await Oid4vpHolderBuilder(
            kms: kms,
            vault: vault,
            clientId: Constants.clientId,
            httpClient: ReqwestHttpClient.insecure(),
            nonceHandler: nil
        ).build()
    }
}
