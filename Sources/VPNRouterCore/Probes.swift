import Foundation

/// One socket as `nettop -n -x -J interface,state` prints it, e.g.
/// `tcp4 192.168.1.2:64917<->17.57.146.140:5223,en0,Established,`.
/// The interface is the kernel's own account of where the flow goes, which is
/// what makes the traffic view an observation rather than a guess from rules.
public struct ObservedFlow: Equatable, Sendable {
    public var proto: String
    public var address: String
    public var port: String
    public var interface: String

    public init(proto: String, address: String, port: String, interface: String) {
        self.proto = proto
        self.address = address
        self.port = port
        self.interface = interface
    }

    /// nil for anything that is not an outbound flow worth showing: process
    /// rows, the header, listeners, unconnected UDP and loopback.
    public static func parse(_ line: String) -> ObservedFlow? {
        let columns = line.split(separator: ",", omittingEmptySubsequences: false)
        guard columns.count >= 2 else { return nil }
        let socket = columns[0].split(separator: " ")
        guard socket.count == 2, let kind = socket.first, kind.hasPrefix("tcp") || kind.hasPrefix("udp") else { return nil }
        let ends = socket[1].components(separatedBy: "<->")
        let interface = String(columns[1])
        guard ends.count == 2, !interface.isEmpty, interface != "lo0" else { return nil }
        // IPv4 puts the port after ":", IPv6 after the "." that follows its last colon.
        guard let cut = ends[1].lastIndex(of: kind.hasSuffix("6") ? "." : ":") else { return nil }
        let address = String(ends[1][..<cut])
        let port = String(ends[1][ends[1].index(after: cut)...])
        guard IPAddress(address) != nil, port != "*" else { return nil }
        // Link-local peers (AirDrop and Continuity on awdl0) never leave the link,
        // so which VPN carries them is not a question.
        if address.lowercased().hasPrefix("fe80:") || address.hasPrefix("169.254.") { return nil }
        return .init(proto: String(kind.prefix(3)), address: address, port: port, interface: interface)
    }

    /// The process row that heads its flows: `Google Chrome He.812,,,` →
    /// `("Google Chrome He", 812)`. nettop cuts the name to 16 characters.
    public static func process(_ line: String) -> (name: String, pid: Int32)? {
        guard let first = line.split(separator: ",", omittingEmptySubsequences: false).first,
              parse(line) == nil, !first.hasPrefix("tcp"), !first.hasPrefix("udp"),
              let dot = first.lastIndex(of: "."), dot != first.startIndex,
              let pid = Int32(first[first.index(after: dot)...])
        else { return nil }
        return (String(first[..<dot]), pid)
    }
}

public enum HostResolver {
    /// Every address the system resolver gives, in its preferred order; an
    /// address comes back as itself. Blocks, so call it off any actor the
    /// resolver's answer depends on.
    public static func addresses(_ host: String) -> [String] {
        if IPAddress(host) != nil { return [host] }
        var hints = addrinfo(ai_flags: AI_ADDRCONFIG, ai_family: AF_UNSPEC, ai_socktype: SOCK_DGRAM, ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, nil, &hints, &result) == 0 else { return [] }
        defer { freeaddrinfo(result) }
        var addresses: [String] = []
        var cursor = result
        while let info = cursor?.pointee {
            var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
            if getnameinfo(info.ai_addr, info.ai_addrlen, &buffer, socklen_t(buffer.count), nil, 0, NI_NUMERICHOST) == 0 {
                let end = buffer.firstIndex(of: 0) ?? buffer.endIndex
                addresses.append(String(decoding: buffer[..<end].map { UInt8(bitPattern: $0) }, as: UTF8.self))
            }
            cursor = info.ai_next
        }
        return addresses
    }

    /// The address's PTR name, nil when it has none. Blocks like `addresses`.
    public static func name(_ address: String) -> String? {
        var hints = addrinfo(ai_flags: AI_NUMERICHOST, ai_family: AF_UNSPEC, ai_socktype: SOCK_DGRAM, ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(address, nil, &hints, &result) == 0, let info = result?.pointee else { return nil }
        defer { freeaddrinfo(result) }
        var buffer = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(info.ai_addr, info.ai_addrlen, &buffer, socklen_t(buffer.count), nil, 0, NI_NAMEREQD) == 0 else { return nil }
        let end = buffer.firstIndex(of: 0) ?? buffer.endIndex
        return String(decoding: buffer[..<end].map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}

public enum PingOutput {
    /// The average from `round-trip min/avg/max/stddev = 0.081/0.133/0.168/0.037 ms`;
    /// nil when no reply came back and ping printed no such line.
    public static func averageMilliseconds(_ output: String) -> Double? {
        guard let line = output.split(separator: "\n").first(where: { $0.contains("round-trip") }),
              let values = line.split(separator: "=").last?.trimmingCharacters(in: .whitespaces).split(separator: "/"),
              values.count >= 2
        else { return nil }
        return Double(values[1])
    }
}
