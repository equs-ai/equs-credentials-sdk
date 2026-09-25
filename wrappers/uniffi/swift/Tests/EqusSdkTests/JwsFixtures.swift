import Foundation
@testable import EqusSdk

/// Mints real, freshly-signed compact JWS/JWTs in-process, the way `equs-test-fixtures`'
/// `jws::sign_compact` does in Rust -- for the handful of fixtures the generated bundle can't
/// reproduce (an OID4VP request object carrying a `presentation_definition` query -- no OID4VP
/// verifier is exposed to the Swift UniFFI bindings, only `Oid4vpHolder` -- and a `did:web`-issued
/// credential) because no equivalent builder is exposed here. Uses only primitives already on the
/// Swift test classpath: `InMemKms`, `DidKey`, `KeyHandle.sign`.
enum JwsFixtures {
    static func b64url(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    static func jsonBytes(_ object: [String: Any]) -> Data {
        // JSONSerialization doesn't guarantee key order and that's fine here: the SDK parses and
        // re-serializes with its own canonical order on the way back out, and nothing in this repo
        // compares a signed JWS's raw bytes -- only its decoded content matters.
        try! JSONSerialization.data(withJSONObject: object, options: [])
    }

    /// A fresh P-256 signing key together with its `did:key` and verification-method URL
    /// (`did#fragment`, as did:key mandates -- see `src/did/didkey.rs`'s own `SAMPLE_DID_URL`
    /// test constant).
    struct SigningKey {
        let did: String
        let didUrl: String
        let keyHandle: WrappedKeyHandle
    }

    static func newSigningKey() async throws -> SigningKey {
        let kms = InMemKms()
        let kid = try await kms.create(kt: KeyType.p256)
        let keyHandle = try await kms.get(kid: kid)
        let did = try DidKey().generate(key: keyHandle)
        let didUrl = "\(did)#\(did.replacingOccurrences(of: "did:key:", with: ""))"
        return SigningKey(did: did, didUrl: didUrl, keyHandle: keyHandle)
    }

    /// Signs `payload` under `header` with `key`.
    static func sign(header: [String: Any], payload: [String: Any], key: SigningKey) async throws -> String {
        let signingInput = "\(b64url(jsonBytes(header))).\(b64url(jsonBytes(payload)))"
        let signature = try await key.keyHandle.inner.sign(payload: signingInput.data(using: .utf8)!)
        return "\(signingInput).\(b64url(signature))"
    }

    /// Signs `payload` under `header`, generating a fresh P-256 key. Returns the compact JWS
    /// together with the signing key's `did:key` and its verification-method URL.
    static func signCompact(header: [String: Any], payload: [String: Any]) async throws -> (
        jwt: String, did: String, didUrl: String
    ) {
        let key = try await newSigningKey()
        let jwt = try await sign(header: header, payload: payload, key: key)
        return (jwt, key.did, key.didUrl)
    }
}
