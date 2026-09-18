import Darwin
import Foundation

public enum IPFamily: Int32, Codable, Sendable {
    case v4 = 2
    case v6 = 30
}

public struct IPAddress: Hashable, Codable, Sendable, CustomStringConvertible {
    public let family: IPFamily
    public let bytes: [UInt8]

    public init?(_ string: String) {
        var v4 = in_addr()
        if inet_pton(AF_INET, string, &v4) == 1 {
            family = .v4
            bytes = withUnsafeBytes(of: &v4) { Array($0) }
            return
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, string, &v6) == 1 {
            family = .v6
            bytes = withUnsafeBytes(of: &v6) { Array($0) }
            return
        }
        return nil
    }

    public init?(family: IPFamily, bytes: [UInt8]) {
        guard bytes.count == (family == .v4 ? 4 : 16) else { return nil }
        self.family = family
        self.bytes = bytes
    }

    public var description: String {
        var storage = bytes
        var output = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let familyValue = family == .v4 ? AF_INET : AF_INET6
        return storage.withUnsafeMutableBytes { raw in
            inet_ntop(familyValue, raw.baseAddress, &output, socklen_t(output.count)).map(String.init(cString:)) ?? ""
        }
    }
}

public struct CIDR: Hashable, Codable, Sendable, CustomStringConvertible {
    public let address: IPAddress
    public let prefixLength: Int

    public init?(_ string: String) {
        let parts = string.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let address = IPAddress(String(parts[0])),
              let prefix = Int(parts[1]),
              (0...(address.family == .v4 ? 32 : 128)).contains(prefix)
        else { return nil }
        self.address = Self.networkAddress(address, prefix: prefix)
        self.prefixLength = prefix
    }

    public init(address: IPAddress, prefixLength: Int) {
        self.address = Self.networkAddress(address, prefix: prefixLength)
        self.prefixLength = prefixLength
    }

    public func contains(_ candidate: IPAddress) -> Bool {
        guard candidate.family == address.family else { return false }
        let wholeBytes = prefixLength / 8
        let remainingBits = prefixLength % 8
        guard address.bytes.prefix(wholeBytes) == candidate.bytes.prefix(wholeBytes) else { return false }
        guard remainingBits > 0 else { return true }
        let mask = UInt8.max << (8 - remainingBits)
        return address.bytes[wholeBytes] & mask == candidate.bytes[wholeBytes] & mask
    }

    public var description: String { "\(address)/\(prefixLength)" }

    /// A /0 or a /1 half: redirect-gateway spelled as routes. It would take over the
    /// system default route or collide with the AmneziaWG halves, and whatever
    /// already sits at that destination the route controller adopts and deletes on
    /// shutdown — the system's own default route included.
    public var coversDefault: Bool { prefixLength <= 1 }

    private static func networkAddress(_ address: IPAddress, prefix: Int) -> IPAddress {
        var bytes = address.bytes
        for index in bytes.indices {
            let bitsBeforeByte = index * 8
            if bitsBeforeByte >= prefix { bytes[index] = 0 }
            else if bitsBeforeByte + 8 > prefix { bytes[index] &= UInt8.max << (8 - (prefix - bitsBeforeByte)) }
        }
        return IPAddress(family: address.family, bytes: bytes)!
    }
}
