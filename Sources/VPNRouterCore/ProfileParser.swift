import Compression
import Foundation

/// One `remote` line of a profile: a server openvpn may connect to.
public struct OpenVPNRemote: Codable, Hashable, Sendable {
    public var host: String
    public var port: String?
    public var proto: String?

    public init(host: String, port: String? = nil, proto: String? = nil) {
        self.host = host
        self.port = port
        self.proto = proto
    }
}

public struct OpenVPNProfile: Sendable {
    public let sanitizedConfiguration: String
    public let dangerousDirectives: [String]
    public let staticRoutes: [String]
    public let remoteHosts: [String]
    public let requiresCredentials: Bool
    /// In the profile's order, which is the order openvpn tries them in.
    public let remotes: [OpenVPNRemote]
    /// Where each remote's line sits in the sanitized configuration.
    let remoteLines: [Int]

    /// The configuration with `remote` tried first; openvpn falls back to the
    /// rest in their order, as it would have anyway.
    public func configuration(preferring remote: OpenVPNRemote?) -> String {
        guard let remote, let chosen = remotes.firstIndex(of: remote) else { return sanitizedConfiguration }
        var lines = sanitizedConfiguration.components(separatedBy: "\n")
        let line = lines.remove(at: remoteLines[chosen])
        lines.insert(line, at: remoteLines[0])
        // A picked server is no pick under remote-random, which reshuffles them all.
        lines.removeAll { line in
            let directive = OpenVPNProfileParser.tokenize(line.trimmingCharacters(in: .whitespaces)).first?.lowercased()
            return directive == "remote-random" || directive == "--remote-random"
        }
        return lines.joined(separator: "\n")
    }
}

public enum OpenVPNProfileParser {
    // "engine", and any provider but OpenSSL's own, load native code as root even
    // without script-security, which is all that gates the script hooks.
    private static let dangerous = Set([
        "up", "down", "route-up", "route-pre-down", "ipchange", "plugin", "engine",
        "tls-verify", "auth-user-pass-verify", "client-connect", "client-disconnect", "learn-address",
    ])
    private static let linuxDNSHelpers = Set(["update-resolv-conf", "update-resolv-conf.sh", "update-systemd-resolved"])
    private static let builtinProviders = Set(["default", "legacy", "base", "fips", "null"])
    private static let controlled = Set([
        "management", "management-client", "management-hold", "management-query-passwords",
        "management-up-down", "daemon", "writepid", "route-noexec", "redirect-gateway",
        "redirect-private", "log", "log-append", "status", "script-security", "tmp-dir",
        "replay-persist", "cd", "chroot", "user", "group", "nice", "syslog",
    ])
    private static let externalFiles = Set([
        "ca", "cert", "key", "pkcs12", "tls-auth", "tls-crypt", "tls-crypt-v2", "crl-verify",
        "secret", "askpass", "http-proxy-user-pass", "auth-gen-token-secret", "extra-certs",
    ])

    public static func parse(_ text: String, allowUnsafe: Bool = false) throws -> OpenVPNProfile {
        guard !text.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            throw RouterErrorInfo(.invalidConfiguration, "OpenVPN-конфигурация пуста")
        }

        let lines = text.components(separatedBy: .newlines)
        var output: [String] = []
        var dangerousLines: [String] = []
        var routes: [String] = []
        var remoteHosts: [String] = []
        var remotes: [OpenVPNRemote] = []
        var remoteLines: [Int] = []
        var currentInline: String?
        var hasTun = false
        var hasTap = false
        var requiresCredentials = false

        for original in lines {
            let trimmed = original.trimmingCharacters(in: .whitespaces)
            if trimmed.hasPrefix("<"), trimmed.hasSuffix(">"), !trimmed.hasPrefix("</") {
                let tag = String(trimmed.dropFirst().dropLast()).lowercased()
                // Its directives would skip every check below, and its remote would
                // never reach the firewall's pass list, so it could not connect anyway.
                guard tag != "connection" else {
                    throw RouterErrorInfo(.invalidConfiguration, "Блоки <connection> не поддерживаются: перенесите remote в основной профиль")
                }
                currentInline = tag
                output.append(original)
                continue
            }
            if trimmed.hasPrefix("</") {
                currentInline = nil
                output.append(original)
                continue
            }
            if currentInline != nil {
                output.append(original)
                continue
            }
            if trimmed.isEmpty || trimmed.hasPrefix("#") || trimmed.hasPrefix(";") {
                output.append(original)
                continue
            }

            let tokens = tokenize(trimmed)
            guard let rawDirective = tokens.first?.lowercased() else { continue }
            let directive = rawDirective.hasPrefix("--") ? String(rawDirective.dropFirst(2)) : rawDirective
            if directive == "config" {
                throw RouterErrorInfo(.invalidConfiguration, "Вложенные OpenVPN config-файлы не поддерживаются")
            }
            if directive == "dev" || directive == "dev-type" {
                let value = tokens.dropFirst().first?.lowercased() ?? ""
                hasTap = hasTap || value.hasPrefix("tap")
                hasTun = hasTun || value.hasPrefix("tun")
            }
            if directive == "auth-user-pass" {
                requiresCredentials = true
                if tokens.count > 1 {
                    throw RouterErrorInfo(.invalidConfiguration, "Файл auth-user-pass не поддерживается; введите логин и пароль в приложении")
                }
            }
            // Only the inline form: a path here is a file that root openvpn would read.
            if externalFiles.contains(directive), tokens.count > 1, tokens[1].lowercased() != "[inline]" {
                throw RouterErrorInfo(.invalidConfiguration, "Профиль должен содержать <\(directive)> внутри .ovpn")
            }
            if directive == "route", tokens.count >= 2 {
                let mask = tokens.count >= 3 ? tokens[2] : "255.255.255.255"
                guard let route = normalizedIPv4Route(tokens[1], mask: mask) else {
                    throw RouterErrorInfo(.invalidConfiguration, "Некорректный OpenVPN route: \(trimmed)")
                }
                if !route.coversDefault { routes.append(route.description) }
                continue
            }
            if directive == "route-ipv6", tokens.count >= 2 {
                guard let route = CIDR(tokens[1]), route.address.family == .v6 else {
                    throw RouterErrorInfo(.invalidConfiguration, "Некорректный OpenVPN route-ipv6: \(trimmed)")
                }
                if !route.coversDefault { routes.append(route.description) }
                continue
            }
            if directive == "remote", tokens.count >= 2 {
                remoteHosts.append(tokens[1])
                remotes.append(.init(host: tokens[1], port: tokens.count > 2 ? tokens[2] : nil, proto: tokens.count > 3 ? tokens[3] : nil))
                // Appended below as it is: nothing filters a remote line out.
                remoteLines.append(output.count)
            }
            // Linux DNS helpers that providers ship profiles with: absent on macOS,
            // where openvpn refuses to start over them, and the daemon sets DNS itself.
            if directive == "up" || directive == "down", tokens.count > 1,
               linuxDNSHelpers.contains(tokens[1].components(separatedBy: "/").last ?? "") { continue }
            let loadsCode = dangerous.contains(directive)
                || (directive == "providers" && !tokens.dropFirst().allSatisfy { builtinProviders.contains($0.lowercased()) })
            if loadsCode {
                dangerousLines.append(trimmed)
                if !allowUnsafe { continue }
            }
            if controlled.contains(directive) || directive.hasPrefix("management-") { continue }
            output.append(original)
        }

        guard !hasTap else { throw RouterErrorInfo(.invalidConfiguration, "TAP/bridge не поддерживается; требуется TUN-профиль") }
        guard hasTun else { throw RouterErrorInfo(.invalidConfiguration, "В профиле отсутствует dev tun") }

        output.append(contentsOf: [
            "route-noexec",
            "pull-filter ignore redirect-gateway",
            "auth-retry interact",
        ])
        if allowUnsafe, !dangerousLines.isEmpty { output.append("script-security 2") }
        return OpenVPNProfile(
            sanitizedConfiguration: output.joined(separator: "\n") + "\n",
            dangerousDirectives: dangerousLines,
            staticRoutes: routes,
            remoteHosts: remoteHosts,
            requiresCredentials: requiresCredentials,
            remotes: remotes,
            remoteLines: remoteLines
        )
    }

    public static func pushedOptions(from line: String) -> (routes: [String], dns: [String], domains: [String]) {
        guard let range = line.range(of: "PUSH_REPLY,") else { return ([], [], []) }
        let values = line[range.upperBound...].split(separator: ",").map(String.init)
        var routes: [String] = []
        var dns: [String] = []
        var domains: [String] = []
        for value in values {
            let tokens = tokenize(value)
            guard !tokens.isEmpty else { continue }
            switch tokens[0].lowercased() {
            case "route" where tokens.count >= 2:
                let mask = tokens.count >= 3 ? tokens[2] : "255.255.255.255"
                if let route = normalizedIPv4Route(tokens[1], mask: mask), !route.coversDefault { routes.append(route.description) }
            case "route-ipv6" where tokens.count >= 2:
                if let route = CIDR(tokens[1]), route.address.family == .v6, !route.coversDefault { routes.append(route.description) }
            case "dhcp-option" where tokens.count >= 3 && tokens[1].uppercased() == "DNS":
                if let address = IPAddress(tokens[2]) { dns.append(address.description) }
            case "dhcp-option" where tokens.count >= 3 && ["DOMAIN", "DOMAIN-SEARCH"].contains(tokens[1].uppercased()):
                domains.append(tokens[2])
            default: break
            }
        }
        return (routes, dns, domains)
    }

    fileprivate static func tokenize(_ line: String) -> [String] {
        var result: [String] = []
        var token = ""
        var quote: Character?
        for character in line {
            if let activeQuote = quote {
                if character == activeQuote { quote = nil } else { token.append(character) }
            } else if character == "\"" || character == "'" {
                quote = character
            } else if character == " " || character == "\t" {
                if !token.isEmpty { result.append(token); token = "" }
            } else {
                token.append(character)
            }
        }
        if !token.isEmpty { result.append(token) }
        return result
    }

    private static func prefixLength(fromIPv4Mask mask: String) -> Int? {
        guard let address = IPAddress(mask), address.family == .v4 else { return nil }
        let bits = address.bytes.flatMap { byte in (0..<8).reversed().map { (byte >> $0) & 1 } }
        guard !bits.enumerated().contains(where: { index, value in value == 1 && bits.prefix(index).contains(0) }) else { return nil }
        return bits.reduce(0) { $0 + Int($1) }
    }

    private static func normalizedIPv4Route(_ value: String, mask: String) -> CIDR? {
        guard let address = IPAddress(value), address.family == .v4,
              let prefix = prefixLength(fromIPv4Mask: mask)
        else { return nil }
        return CIDR(address: address, prefixLength: prefix)
    }
}

public struct AmneziaWGProfile: Sendable {
    public let setConf: String
    public let addresses: [String]
    public let dnsServers: [String]
    public let endpoint: String
    public let supportsIPv6: Bool
    public let mtu: Int?

    /// The endpoint without its port: what a resolver, a route and a pass rule take.
    public var endpointHost: String {
        if endpoint.hasPrefix("["), let end = endpoint.firstIndex(of: "]") {
            return String(endpoint[endpoint.index(after: endpoint.startIndex)..<end])
        }
        return endpoint.split(separator: ":").first.map(String.init) ?? endpoint
    }
}

public enum AmneziaWGProfileParser {
    public static func parse(_ text: String) throws -> AmneziaWGProfile {
        var section = ""
        var interfaceLines: [String] = []
        var peerSections: [[String]] = []
        var currentPeer: [String] = []
        var addresses: [String] = []
        var dns: [String] = []
        var endpoint: String?
        var mtu: Int?
        var defaultPeers = 0
        var currentPeerHasDefault = false
        var currentPeerHasKeepalive = false
        var supportsIPv6 = false

        func finishPeer() {
            guard !currentPeer.isEmpty else { return }
            var peer = currentPeer
            if !currentPeerHasKeepalive { peer.append("PersistentKeepalive = 25") }
            peerSections.append(peer)
            if currentPeerHasDefault { defaultPeers += 1 }
        }

        for raw in text.components(separatedBy: .newlines) {
            let line = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            if line.isEmpty || line.hasPrefix("#") || line.hasPrefix(";") { continue }
            if line.hasPrefix("[") && line.hasSuffix("]") {
                if section == "peer" { finishPeer(); currentPeer = []; currentPeerHasDefault = false; currentPeerHasKeepalive = false }
                section = String(line.dropFirst().dropLast()).lowercased()
                guard section == "interface" || section == "peer" else {
                    throw RouterErrorInfo(.invalidConfiguration, "Неизвестная секция AWG: \(line)")
                }
                continue
            }
            // Split on the first "=" by index: `split` drops empty fields, so a
            // blank knob like "I2 =" would look like a line with no separator at
            // all, and a base64 key ending in "=" must keep its padding.
            guard let separator = line.firstIndex(of: "=") else {
                throw RouterErrorInfo(.invalidConfiguration, "Некорректная строка AWG: \(line)")
            }
            let rawKey = String(line[..<separator]).trimmingCharacters(in: .whitespaces)
            let value = String(line[line.index(after: separator)...]).trimmingCharacters(in: .whitespaces)
            guard !rawKey.isEmpty else { throw RouterErrorInfo(.invalidConfiguration, "Некорректная строка AWG: \(line)") }
            let key = rawKey.lowercased()
            if section == "interface" {
                switch key {
                case "address": addresses += value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                case "dns": dns += value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                // Dropping MTU silently blackholes large packets on links that
                // need a smaller one; routing tables stay ours, so "table" does not.
                case "mtu":
                    guard let value = Int(value), (1280...9000).contains(value) else {
                        throw RouterErrorInfo(.invalidConfiguration, "Некорректный MTU в AWG-профиле")
                    }
                    mtu = value
                case "table": break
                case "preup", "postup", "predown", "postdown":
                    throw RouterErrorInfo(.invalidConfiguration, "Скрипты в AWG-профиле не поддерживаются")
                // I1..I5 are routinely left blank; an empty knob sets nothing and
                // awg setconf rejects a bare "I2 =".
                default: if !value.isEmpty { interfaceLines.append("\(rawKey) = \(value)") }
                }
            } else if section == "peer" {
                if !value.isEmpty { currentPeer.append("\(rawKey) = \(value)") }
                if key == "endpoint" { endpoint = value }
                if key == "persistentkeepalive" { currentPeerHasKeepalive = true }
                if key == "allowedips" {
                    let values = value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                    // AllowedIPs may span several lines, each adding to the list.
                    currentPeerHasDefault = currentPeerHasDefault || values.contains("0.0.0.0/0")
                    supportsIPv6 = supportsIPv6 || values.contains("::/0")
                }
            } else {
                throw RouterErrorInfo(.invalidConfiguration, "Параметр AWG находится вне секции")
            }
        }
        if section == "peer" { finishPeer() }

        guard !addresses.isEmpty else { throw RouterErrorInfo(.invalidConfiguration, "В AWG-профиле отсутствует Address") }
        guard addresses.allSatisfy({ CIDR($0) != nil }), addresses.contains(where: { !$0.contains(":") }) else {
            throw RouterErrorInfo(.invalidConfiguration, "AWG Address должен содержать корректный IPv4 CIDR")
        }
        guard dns.allSatisfy({ IPAddress($0) != nil }) else {
            throw RouterErrorInfo(.invalidConfiguration, "Некорректный DNS в AWG-профиле")
        }
        guard interfaceLines.contains(where: { $0.lowercased().hasPrefix("privatekey ") }) else {
            throw RouterErrorInfo(.invalidConfiguration, "В AWG-профиле отсутствует PrivateKey")
        }
        guard defaultPeers == 1 else {
            throw RouterErrorInfo(.invalidConfiguration, "Ровно один AWG peer должен содержать 0.0.0.0/0")
        }
        guard peerSections.count == 1 else {
            throw RouterErrorInfo(.invalidConfiguration, "MVP поддерживает ровно один AWG peer")
        }
        guard let endpoint, !endpoint.isEmpty else { throw RouterErrorInfo(.invalidConfiguration, "В AWG-профиле отсутствует Endpoint") }
        guard validEndpoint(endpoint) else { throw RouterErrorInfo(.invalidConfiguration, "Некорректный AWG Endpoint") }

        var rendered = ["[Interface]"] + interfaceLines
        for peer in peerSections { rendered += ["", "[Peer]"] + peer }
        return .init(
            setConf: rendered.joined(separator: "\n") + "\n",
            addresses: addresses,
            dnsServers: dns,
            endpoint: endpoint,
            supportsIPv6: supportsIPv6,
            mtu: mtu
        )
    }

    private static func validEndpoint(_ value: String) -> Bool {
        let portText: String
        let host: String
        if value.hasPrefix("["), let end = value.firstIndex(of: "]"), value.index(after: end) < value.endIndex,
           value[value.index(after: end)] == ":" {
            host = String(value[value.index(after: value.startIndex)..<end])
            portText = String(value[value.index(end, offsetBy: 2)...])
        } else {
            let parts = value.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count == 2 else { return false }
            host = String(parts[0]); portText = String(parts[1])
        }
        guard let port = Int(portText), (1...65_535).contains(port) else { return false }
        return IPAddress(host) != nil || RuleSet.normalizeDomain(host) != nil
    }

    /// Amnezia's «Поделиться VPN» link: base64url of a Qt `qCompress` blob
    /// (4-byte big-endian uncompressed size, then a zlib stream) that inflates
    /// to JSON. An AmneziaWG or WireGuard container in it keeps, in `last_config`
    /// (itself a JSON string), the same `.conf` text a manual export gives, under
    /// `config`; the ordinary `.conf` parser takes it from there.
    public static func nativeConfig(fromVpnLink text: String) throws -> String {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix("vpn://") else {
            throw RouterErrorInfo(.invalidConfiguration, "Ожидалась ссылка вида vpn://…")
        }
        var base64 = String(trimmed.dropFirst("vpn://".count))
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while base64.count % 4 != 0 { base64 += "=" }
        guard let compressed = Data(base64Encoded: base64), compressed.count > 6 else {
            throw RouterErrorInfo(.invalidConfiguration, "Не удалось декодировать ссылку vpn://")
        }
        let expectedSize = compressed.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
        // Apple's COMPRESSION_ZLIB is raw DEFLATE: the 2-byte zlib header Qt
        // writes has to go; the Adler-32 trailer is simply left unread.
        guard let json = zlibInflate(compressed.dropFirst(6), expectedSize: expectedSize),
              let root = try? JSONSerialization.jsonObject(with: json) as? [String: Any],
              let containers = root["containers"] as? [[String: Any]]
        else {
            throw RouterErrorInfo(.invalidConfiguration, "Не удалось распаковать ссылку vpn://")
        }
        // Keyed by protocol, not by container name: "amnezia-awg" and the newer
        // "amnezia-awg2" both keep theirs under "awg".
        for container in containers {
            guard let proto = (container["awg"] ?? container["wireguard"]) as? [String: Any],
                  let lastConfigText = (proto["last_config"] as? String)?.data(using: .utf8),
                  let lastConfig = try? JSONSerialization.jsonObject(with: lastConfigText) as? [String: Any],
                  var config = lastConfig["config"] as? String, !config.isEmpty
            else { continue }
            // Amnezia stores the template's DNS placeholders and fills them from
            // the link's top-level dns1/dns2 only at connect time; its defaults
            // apply when those are missing.
            let primary = (root["dns1"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "1.1.1.1"
            let secondary = (root["dns2"] as? String).flatMap { $0.isEmpty ? nil : $0 } ?? "1.0.0.1"
            config = config
                .replacingOccurrences(of: "$PRIMARY_DNS", with: primary)
                .replacingOccurrences(of: "$SECONDARY_DNS", with: secondary)
            // The text carries no MTU line; Amnezia runs it with the MTU kept beside it.
            if let mtu = lastConfig["mtu"] as? String, !mtu.isEmpty,
               !config.lowercased().contains("\nmtu"), let header = config.range(of: "[Interface]") {
                config.insert(contentsOf: "\nMTU = \(mtu)", at: header.upperBound)
            }
            return config
        }
        throw RouterErrorInfo(.invalidConfiguration, "В ссылке vpn:// нет готового профиля AmneziaWG — поделитесь соединением в Amnezia («Поделиться VPN»)")
    }

    private static func zlibInflate(_ data: Data, expectedSize: Int) -> Data? {
        // The size comes from the link itself; a profile is a few KB.
        guard (1...(1 << 20)).contains(expectedSize) else { return nil }
        var output = [UInt8](repeating: 0, count: expectedSize)
        let source = [UInt8](data)
        let decodedCount = output.withUnsafeMutableBufferPointer { dst in
            source.withUnsafeBufferPointer { src in
                compression_decode_buffer(dst.baseAddress!, expectedSize, src.baseAddress!, src.count, nil, COMPRESSION_ZLIB)
            }
        }
        guard decodedCount == expectedSize else { return nil }
        return Data(output)
    }
}
