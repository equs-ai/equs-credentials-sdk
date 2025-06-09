import Testing
import Foundation
import Swifter
@testable import Asdk

@Suite(.serialized) class HttpTests {

	let server: HttpServer

	init() async throws {
		self.server = HttpServer()
		try server.start(9003)
	}

	deinit {
		server.stop()
	}

	@Test func asyncCall() async throws {
		let client = MockHttpClient()

		let request = Asdk.HttpRequest(
			url: "http://localhost:9003/get",
			method: Asdk.HttpMethod.get,
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
		let request = Asdk.HttpRequest(
			url: "http://localhost:9003/get",
			method: Asdk.HttpMethod.get,
			headers: ["accept": "application/json"],
			body: nil
		)
		let response = try await client.asyncCall(request: request)

		#expect("{\"message\": \"ok\"}" == response.body)
	}

	@Test func reqwestInsecureAsyncCallShouldThrowErrorOnSecureUrl() async throws {
		let client = try ReqwestHttpClient()
		let request = Asdk.HttpRequest(
			url: "http://localhost:9003/get",
			method: Asdk.HttpMethod.get,
			headers: ["accept": "application/json"],
			body: nil
		)

		do {
			_ = try await client.asyncCall(request: request)
			#expect(Bool(false), "Expected HttpAsyncCall error to be thrown")
		} catch let error as Asdk.Error {
			switch error {
			case .HttpAsyncCall(let message):
				#expect(message.contains("builder error for url"))
			default:
				#expect(Bool(false), "Unexpected Asdk.Error case: \(error)")
			}
		} catch {
			#expect(Bool(false), "Unexpected error type: \(error)")
		}
	}

}

final class MockHttpClient: Asdk.HttpClient {
	func asyncCall(request: Asdk.HttpRequest) async throws -> Asdk.HttpResponse {
		return Asdk.HttpResponse(
			statusCode: 200,
			headers: ["content-type": "application/json"],
			body: "{\"message\": \"ok\"}"
		)
	}
}
