import Testing
import Foundation
import Swifter
@testable import EqusSdk

private func netdiagResolve(_ host: String) {
	var hints = addrinfo(
		ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_protocol: 0,
		ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
	var res: UnsafeMutablePointer<addrinfo>?
	let start = Date()
	let rc = getaddrinfo(host, nil, &hints, &res)
	let elapsed = Date().timeIntervalSince(start)
	print(String(format: "NETDIAG resolve %@ rc=%d in %.3fs", host, rc, elapsed))
	var node = res
	while let cur = node {
		var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
		if getnameinfo(cur.pointee.ai_addr, cur.pointee.ai_addrlen, &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
			let fam = cur.pointee.ai_family == AF_INET6 ? "INET6" : "INET"
			print("NETDIAG   -> \(fam) \(String(cString: buf))")
		}
		node = cur.pointee.ai_next
	}
	freeaddrinfo(res)
}

private func netdiagConnect(_ addr: String, family: Int32, port: in_port_t) {
	let fd = socket(family, SOCK_STREAM, 0)
	guard fd >= 0 else { print("NETDIAG connect \(addr) socket() failed errno=\(errno)"); return }
	defer { close(fd) }
	let start = Date()
	var rc: Int32 = -1
	if family == AF_INET {
		var sa = sockaddr_in()
		sa.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
		sa.sin_family = sa_family_t(AF_INET)
		sa.sin_port = port.bigEndian
		inet_pton(AF_INET, addr, &sa.sin_addr)
		rc = withUnsafePointer(to: &sa) {
			$0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
				connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
			}
		}
	} else {
		var sa = sockaddr_in6()
		sa.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
		sa.sin6_family = sa_family_t(AF_INET6)
		sa.sin6_port = port.bigEndian
		inet_pton(AF_INET6, addr, &sa.sin6_addr)
		rc = withUnsafePointer(to: &sa) {
			$0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
				connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in6>.size))
			}
		}
	}
	let elapsed = Date().timeIntervalSince(start)
	print(String(format: "NETDIAG connect %@ rc=%d errno=%d in %.3fs", addr, rc, rc == 0 ? 0 : errno, elapsed))
}

private func netdiagHttp(_ label: String, _ url: String) async {
	let t0 = Date()
	do {
		let client = try ReqwestHttpClient.insecure()
		let built = Date().timeIntervalSince(t0)
		let request = EqusSdk.HttpRequest(
			url: url, method: EqusSdk.HttpMethod.get,
			headers: ["accept": "application/json"], body: nil)
		let t1 = Date()
		_ = try await client.asyncCall(request: request)
		let called = Date().timeIntervalSince(t1)
		print(String(format: "NETDIAG http[%@] %@ OK  client=%.3fs request=%.3fs total=%.3fs",
			label, url, built, called, Date().timeIntervalSince(t0)))
	} catch {
		print(String(format: "NETDIAG http[%@] %@ FAILED in %.3fs: %@",
			label, url, Date().timeIntervalSince(t0), String(describing: error)))
	}
}

@Suite(.serialized) class NetDiagnostics {
	let server: HttpServer
	let port: in_port_t

	init() throws {
		self.server = HttpServer()
		self.server["/get"] = { _ in
			.ok(.data("{\"message\": \"ok\"}".data(using: .utf8)!, contentType: "application/json"))
		}
		try server.start(0, forceIPv4: true)
		self.port = in_port_t(try server.port())
	}

	@Test func netdiag() async throws {
		print("NETDIAG ---- begin, IPv4-only server on 127.0.0.1:\(port) ----")
		netdiagResolve("localhost")
		netdiagConnect("127.0.0.1", family: AF_INET, port: port)
		netdiagConnect("::1", family: AF_INET6, port: port)
		await netdiagHttp("cold-ip", "http://127.0.0.1:\(port)/get")
		await netdiagHttp("warm-host", "http://localhost:\(port)/get")
		await netdiagHttp("warm-ip", "http://127.0.0.1:\(port)/get")
		await netdiagHttp("warm-host2", "http://localhost:\(port)/get")
		print("NETDIAG ---- end ----")
	}
}
