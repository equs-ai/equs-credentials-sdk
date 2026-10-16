import Foundation
@testable import EqusSdk

/// Routes SDK HTTP calls to canned responses in place of an in-process Swifter
/// server. Matching is on URL path only, so fixture URLs that embed a host and
/// port -- including the ones baked into signed JWTs -- keep working without any
/// socket being bound.
final class MockHttpRouter: EqusSdk.HttpClient, @unchecked Sendable {
	typealias Handler = (EqusSdk.HttpRequest) -> EqusSdk.HttpResponse

	private let lock = NSLock()
	private var routes: [String: Handler] = [:]
	private var seen: [EqusSdk.HttpRequest] = []

	subscript(path: String) -> Handler? {
		get {
			lock.lock()
			defer { lock.unlock() }
			return routes[path]
		}
		set {
			lock.lock()
			defer { lock.unlock() }
			routes[path] = newValue
		}
	}

	/// Requests received so far, in order, for tests that assert a callback fired.
	var requests: [EqusSdk.HttpRequest] {
		lock.lock()
		defer { lock.unlock() }
		return seen
	}

	func asyncCall(request: EqusSdk.HttpRequest) async throws -> EqusSdk.HttpResponse {
		lock.lock()
		seen.append(request)
		let handler = routes[MockHttpRouter.path(of: request.url)]
		lock.unlock()
		guard let handler = handler else {
			return EqusSdk.HttpResponse(
				statusCode: 404, headers: [:], body: "no mock route for \(request.url)")
		}
		return handler(request)
	}

	static func path(of url: String) -> String {
		URLComponents(string: url)?.path ?? url
	}

	static func ok(_ body: String, contentType: String = "application/json") -> EqusSdk.HttpResponse {
		EqusSdk.HttpResponse(statusCode: 200, headers: ["content-type": contentType], body: body)
	}
}
