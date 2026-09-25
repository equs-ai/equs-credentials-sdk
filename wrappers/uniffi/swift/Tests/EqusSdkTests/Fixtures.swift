import Foundation

/// Reads the generated fixture bundle (`equs-test-fixtures`'s `fixture_gen` binary output).
///
/// `swift test` has no pretest hook, so nothing regenerates the bundle automatically the way
/// Task 10's `npm pretest` or this repo's Gradle `fixtureGen` task do. A developer (or CI) runs
/// `wrappers/uniffi/scripts/generate_fixtures.sh` once before `swift test`; that script writes the
/// bundle next to this file by default, which is where `Fixtures` looks unless
/// `EQUS_FIXTURE_BUNDLE` is set to something else.
enum Fixtures {
    private static let generateHint =
        "run: wrappers/uniffi/scripts/generate_fixtures.sh (from the repo root)"

    private static let defaultPath: String = {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("fixtures.generated.json")
            .path
    }()

    private static let bundle: [String: Any] = {
        let path = ProcessInfo.processInfo.environment["EQUS_FIXTURE_BUNDLE"] ?? defaultPath

        guard let data = FileManager.default.contents(atPath: path) else {
            fatalError("fixture bundle missing at \(path) -- \(generateHint)")
        }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            fatalError("fixture bundle at \(path) is not a JSON object -- \(generateHint)")
        }
        return json
    }()

    static func token(_ name: String) -> String {
        guard let value = bundle[name] as? String else {
            fatalError("fixture \(name) is not a token")
        }
        return value
    }

    static func object(_ name: String) -> [String: Any] {
        guard let value = bundle[name] as? [String: Any] else {
            fatalError("fixture \(name) is not an object")
        }
        return value
    }

    /// A naive, unverified decode of a compact JWS's payload segment -- the same trick the
    /// TypeScript suites' `jwt-decode` performs and the Kotlin suite's `Fixtures.claim` performs.
    /// Used only to pull a claim (e.g. `sub`) out of a bundle token whose subject is a fresh
    /// random DID on every generation.
    static func claim(_ token: String, _ name: String) -> String? {
        let segments = token.split(separator: ".", maxSplits: 2)
        guard segments.count >= 2 else { return nil }
        var payload = String(segments[1])
        while payload.count % 4 != 0 { payload += "=" }
        guard let data = Data(base64Encoded: payload.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")) else { return nil }
        guard let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        if let s = json[name] as? String { return s }
        if let n = json[name] { return "\(n)" }
        return nil
    }

    /// The signed JWS part of a compact SD-JWT VC (`header.payload.signature`), stripped of any
    /// `~`-joined disclosures. Presenting a credential selectively drops disclosures the
    /// presentation doesn't need, so this prefix -- not the full compact string -- is what's
    /// guaranteed to still appear verbatim in a presentation built from `token`.
    static func jwsPrefix(_ token: String) -> String {
        String(token.split(separator: "~", maxSplits: 1, omittingEmptySubsequences: false)[0])
    }

    /// The raw `~`-delimited disclosure segment for `claim` within a compact SD-JWT VC, if
    /// present -- i.e. the base64url(`[salt, claim, value]`) segment, unparsed.
    static func disclosure(_ token: String, forClaim claim: String) -> String? {
        let segments = token.split(separator: "~", omittingEmptySubsequences: true)
        for segment in segments.dropFirst() {
            var padded = String(segment)
            while padded.count % 4 != 0 { padded += "=" }
            guard
                let data = Data(
                    base64Encoded: padded.replacingOccurrences(of: "-", with: "+")
                        .replacingOccurrences(of: "_", with: "/"))
            else { continue }
            guard let array = try? JSONSerialization.jsonObject(with: data) as? [Any], array.count >= 2 else {
                continue
            }
            if (array[1] as? String) == claim {
                return String(segment)
            }
        }
        return nil
    }
}
