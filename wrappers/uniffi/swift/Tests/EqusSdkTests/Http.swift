import Testing
import Foundation
import Swifter
@testable import EqusSdk

@Suite(.serialized) class HttpTests {
	let server: HttpServer
	let port: in_port_t

	init() async throws {
		self.server = HttpServer()
		// Bind to port 0 so the OS picks a guaranteed-free port; avoids collisions
		// with whatever else (CI runner, prior job, etc.) might hold a fixed port.
		// forceIPv4 keeps reqwest's 127.0.0.1 connect path reachable under the iOS Simulator.
		try server.start(0, forceIPv4: true)
		self.port = in_port_t(try server.port())
	}

	// No deinit { server.stop() }: Swifter 1.5.0's HttpServer.stop() can race with its
	// background accept loop and crash xctest. With rotating ports, the previous test's
	// server stays alive on its unused port until process exit; harmless.

	@Test func asyncCall() async throws {
		let client = MockHttpClient()

		let request = EqusSdk.HttpRequest(
			url: "http://localhost:\(port)/get",
			method: EqusSdk.HttpMethod.get,
			headers: ["accept": "application/json"],
			body: "{\"message\": \"are you ok?\"}"
		)

		let response = try await client.asyncCall(request: request)
		#expect(response.body == "{\"message\": \"ok\"}")
	}

	@Test func reqwestInsecureAsyncCall() async throws {
		self.server["/get"] = { (request: Swifter.HttpRequest) -> Swifter.HttpResponse in
			return .ok(
				.data(
                    "{\"message\": \"ok\"}".data(using: .utf8)!,
					contentType: "application/json"))
		}

		let client = try ReqwestHttpClient.insecure()
		let request = EqusSdk.HttpRequest(
			url: "http://localhost:\(port)/get",
			method: EqusSdk.HttpMethod.get,
			headers: ["accept": "application/json"],
			body: nil
		)
		let response = try await client.asyncCall(request: request)

		#expect("{\"message\": \"ok\"}" == response.body)
	}

	@Test func reqwestInsecureAsyncCallShouldThrowErrorOnSecureUrl() async throws {
		let client = try ReqwestHttpClient()
		let request = EqusSdk.HttpRequest(
			url: "http://localhost:\(port)/get",
			method: EqusSdk.HttpMethod.get,
			headers: ["accept": "application/json"],
			body: nil
		)

		do {
			_ = try await client.asyncCall(request: request)
			#expect(Bool(false), "Expected HttpAsyncCall error to be thrown")
		} catch let error as EqusSdk.Error {
			switch error {
			case .HttpAsyncCall(let message):
				#expect(message.contains("builder error for url"))
			default:
				#expect(Bool(false), "Unexpected EqusSdk.Error case: \(error)")
			}
		} catch {
			#expect(Bool(false), "Unexpected error type: \(error)")
		}
	}

}

final class MockHttpClient: EqusSdk.HttpClient {
	func asyncCall(request: EqusSdk.HttpRequest) async throws -> EqusSdk.HttpResponse {
		return EqusSdk.HttpResponse(
			statusCode: 200,
			headers: ["content-type": "application/json"],
			body: "{\"message\": \"ok\"}"
		)
	}
}
