@testable import Asdk

final class MockNonceHandler : NonceHandler {
    private let nonce: String
    init(nonce: String) {
        self.nonce = nonce
    }
    func generate() async throws -> String {
        return self.nonce
    }

    func validate(nonce: String) -> Bool {
        return true
    }
}