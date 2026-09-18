import Foundation

public struct DNSQuestion: Equatable, Sendable {
    public let name: String
    public let type: UInt16
}

public struct DNSAddressRecord: Equatable, Sendable {
    public let name: String
    public let address: String
    public let ttl: UInt32
}

public struct DNSCNAMERecord: Equatable, Sendable {
    public let name: String
    public let canonicalName: String
    public let ttl: UInt32
}

public struct DNSMessage: Sendable {
    public let questions: [DNSQuestion]
    public let addresses: [DNSAddressRecord]
    public let cnames: [DNSCNAMERecord]

    public static func parse(_ data: Data) throws -> DNSMessage {
        let bytes = [UInt8](data)
        guard bytes.count >= 12 else { throw RouterErrorInfo(.dnsFailure, "Слишком короткий DNS-пакет") }
        let questionCount = Int(read16(bytes, 4))
        let answerCount = Int(read16(bytes, 6))
        let authorityCount = Int(read16(bytes, 8))
        let additionalCount = Int(read16(bytes, 10))
        let recordCount = answerCount + authorityCount + additionalCount
        guard questionCount <= 64, recordCount <= 512 else { throw RouterErrorInfo(.dnsFailure, "Недопустимый размер DNS-пакета") }
        var offset = 12
        var questions: [DNSQuestion] = []
        for _ in 0..<questionCount {
            let name = try readName(bytes, offset: &offset)
            guard offset + 4 <= bytes.count else { throw RouterErrorInfo(.dnsFailure, "Обрезанный DNS question") }
            questions.append(.init(name: name, type: read16(bytes, offset)))
            offset += 4
        }
        var allAddresses: [DNSAddressRecord] = []
        var cnames: [DNSCNAMERecord] = []
        for _ in 0..<recordCount {
            let name = try readName(bytes, offset: &offset)
            guard offset + 10 <= bytes.count else { throw RouterErrorInfo(.dnsFailure, "Обрезанный DNS answer") }
            let type = read16(bytes, offset)
            let ttl = read32(bytes, offset + 4)
            let length = Int(read16(bytes, offset + 8))
            offset += 10
            guard offset + length <= bytes.count else { throw RouterErrorInfo(.dnsFailure, "Обрезанный DNS rdata") }
            if type == 1, length == 4 {
                allAddresses.append(.init(name: name, address: bytes[offset..<(offset + 4)].map(String.init).joined(separator: "."), ttl: ttl))
            } else if type == 28, length == 16,
                      let address = IPAddress(family: .v6, bytes: Array(bytes[offset..<(offset + 16)])) {
                // Canonical text keeps one address from becoming two table entries.
                allAddresses.append(.init(name: name, address: address.description, ttl: ttl))
            } else if type == 5 {
                var nameOffset = offset
                let canonicalName = try readName(bytes, offset: &nameOffset)
                guard nameOffset <= offset + length else { throw RouterErrorInfo(.dnsFailure, "Некорректный CNAME") }
                cnames.append(.init(name: name, canonicalName: canonicalName, ttl: ttl))
            }
            offset += length
        }

        var reachable: [String: UInt32] = [:]
        for question in questions { reachable[question.name] = .max }
        for _ in 0..<32 {
            var changed = false
            for cname in cnames {
                guard let parentTTL = reachable[cname.name] else { continue }
                let effectiveTTL = min(parentTTL, cname.ttl)
                if reachable[cname.canonicalName].map({ effectiveTTL < $0 }) ?? true {
                    reachable[cname.canonicalName] = effectiveTTL
                    changed = true
                }
            }
            if !changed { break }
        }
        let addresses = allAddresses.compactMap { record -> DNSAddressRecord? in
            guard let chainTTL = reachable[record.name] else { return nil }
            return .init(name: record.name, address: record.address, ttl: min(chainTTL, record.ttl))
        }
        return DNSMessage(questions: questions, addresses: addresses, cnames: cnames)
    }

    /// SERVFAIL for a query we cannot forward, so the client fails fast instead
    /// of hanging until its own timeout. The question and any EDNS record are
    /// echoed back unchanged; a query already carries zero answer records.
    public static func serverFailure(for query: Data) -> Data {
        guard query.count >= 12 else { return Data() }
        var response = Data(query)
        response[2] = (response[2] & 0x7f) | 0x80 // QR = 1, opcode and RD kept
        response[3] = 0x82                        // RA = 1, RCODE = SERVFAIL
        return response
    }

    private static func readName(_ bytes: [UInt8], offset: inout Int) throws -> String {
        var labels: [String] = []
        var cursor = offset
        var jumped = false
        var visited = Set<Int>()
        var jumps = 0
        while true {
            guard cursor < bytes.count else { throw RouterErrorInfo(.dnsFailure, "Обрезанное DNS-имя") }
            let length = Int(bytes[cursor])
            if length == 0 {
                if !jumped { offset = cursor + 1 }
                break
            }
            if length & 0xc0 == 0xc0 {
                guard cursor + 1 < bytes.count else { throw RouterErrorInfo(.dnsFailure, "Обрезанный DNS pointer") }
                let pointer = ((length & 0x3f) << 8) | Int(bytes[cursor + 1])
                guard pointer < bytes.count, visited.insert(pointer).inserted, jumps < 32 else {
                    throw RouterErrorInfo(.dnsFailure, "Зацикленный DNS pointer")
                }
                if !jumped { offset = cursor + 2; jumped = true }
                cursor = pointer
                jumps += 1
                continue
            }
            guard length <= 63, cursor + 1 + length <= bytes.count else { throw RouterErrorInfo(.dnsFailure, "Некорректная DNS label") }
            let labelBytes = bytes[(cursor + 1)..<(cursor + 1 + length)]
            guard let label = String(bytes: labelBytes, encoding: .utf8) else { throw RouterErrorInfo(.dnsFailure, "Некорректная DNS label") }
            labels.append(label.lowercased())
            cursor += 1 + length
            if !jumped { offset = cursor }
        }
        return labels.joined(separator: ".")
    }

    private static func read16(_ bytes: [UInt8], _ offset: Int) -> UInt16 {
        UInt16(bytes[offset]) << 8 | UInt16(bytes[offset + 1])
    }

    private static func read32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(read16(bytes, offset)) << 16 | UInt32(read16(bytes, offset + 2))
    }
}
