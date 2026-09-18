import Foundation

/// One server the Xray exit can use, as the daemon stores it. Its outbounds are
/// cleaned on the way in, so rendering never meets anything a subscription
/// could have smuggled into a root process.
public struct XrayServer: Codable, Equatable, Sendable {
    public var name: String
    public var protocolName: String
    public var host: String
    public var port: Int
    /// A JSON array: the proxy outbound first, then whatever it dials through.
    public var outbounds: String
}

/// What the app shows about the Xray exit. The servers' secrets stay in the daemon.
public struct XraySummary: Codable, Equatable, Sendable {
    public struct Server: Codable, Equatable, Sendable {
        public var name: String
        public var protocolName: String
        /// Where the app pings. An address, not a secret; optional because a
        /// daemon from before they were sent reports neither.
        public var host: String?
        public var port: Int?

        public init(name: String, protocolName: String, host: String? = nil, port: Int? = nil) {
            self.name = name
            self.protocolName = protocolName
            self.host = host
            self.port = port
        }

        public var protocolTitle: String {
            ["vless": "VLESS", "vmess": "VMess", "trojan": "Trojan", "shadowsocks": "Shadowsocks", "hysteria": "Hysteria2"][protocolName]
                ?? protocolName
        }
    }

    public var servers: [Server]
    public var selected: Int
    public var title: String?
    public var fromSubscription: Bool
    public var updatedAt: Date?
    public var usedBytes: Int64?
    public var totalBytes: Int64?
    public var expiresAt: Date?
    public var userAgent: String?
    /// The provider's own words and pages, from the subscription's headers.
    public var announce: String?
    public var supportURL: URL?
    public var webPageURL: URL?

    public init(
        servers: [Server], selected: Int, title: String?, fromSubscription: Bool,
        updatedAt: Date?, usedBytes: Int64?, totalBytes: Int64?, expiresAt: Date?, userAgent: String? = nil,
        announce: String? = nil, supportURL: URL? = nil, webPageURL: URL? = nil
    ) {
        self.servers = servers
        self.selected = selected
        self.title = title
        self.fromSubscription = fromSubscription
        self.updatedAt = updatedAt
        self.usedBytes = usedBytes
        self.totalBytes = totalBytes
        self.expiresAt = expiresAt
        self.userAgent = userAgent
        self.announce = announce
        self.supportURL = supportURL
        self.webPageURL = webPageURL
    }
}

/// A change to the Xray exit: share links or an https subscription URL to
/// replace what is there, a server to switch to, or a subscription refresh.
public struct XrayUpdate: Codable, Sendable {
    public var source: String?
    public var selected: Int?
    public var refresh: Bool
    /// The subscription's User-Agent; empty goes back to ours.
    public var userAgent: String?

    public init(source: String? = nil, selected: Int? = nil, refresh: Bool = false, userAgent: String? = nil) {
        self.source = source
        self.selected = selected
        self.refresh = refresh
        self.userAgent = userAgent
    }
}

/// A fetched subscription and what its headers say about it.
public struct XraySubscription: Sendable {
    public var servers: [XrayServer]
    public var title: String?
    public var usedBytes: Int64?
    public var totalBytes: Int64?
    public var expiresAt: Date?
    /// Seconds, from the hours in `profile-update-interval`.
    public var updateInterval: TimeInterval?
    /// Why the entries we cannot run were dropped; names protocols, never secrets.
    public var skipped: [String] = []
    public var announce: String?
    public var supportURL: URL?
    public var webPageURL: URL?
}

/// The loopback SOCKS door that only the health check knows the password to.
public struct XrayProbe: Sendable {
    public var port: Int
    public var user: String
    public var password: String

    public init(port: Int, user: String, password: String) {
        self.port = port
        self.user = user
        self.password = password
    }
}

public enum XrayProfileParser {
    private static let proxyProtocols: Set<String> = ["vless", "vmess", "trojan", "shadowsocks", "hysteria"]
    /// What a proxy may dial through: another proxy, or a fragmenting freedom.
    private static let hopProtocols = proxyProtocols.union(["freedom"])
    /// Keys that would have root read or write a file, or bend sockets beyond the
    /// proxy's own connection. Dropped wherever they appear, and so is any "…File".
    /// allowInsecure is gone from Xray itself: kept, it would fail the whole config.
    private static let forbiddenKeys: Set<String> = [
        "certificates", "masterKeyLog", "interface", "customSockopt", "masquerade", "reverse", "allowInsecure",
    ]
    private static let shadowsocksMethods: Set<String> = [
        "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
        "xchacha20-poly1305", "xchacha20-ietf-poly1305",
        "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
    ]
    /// The TUN's own address: 198.18/15 is set aside for benchmarking, so it
    /// collides with no LAN and no corporate range.
    private static let gateway = "198.18.0.1/30"

    // MARK: - Input

    /// Share links one per line, as pasted or as a subscription sends them —
    /// plain or base64 — or a Happ-style JSON array of full Xray configs.
    public static func servers(from text: String) throws -> [XrayServer] { try parse(text).servers }

    /// An entry for something we do not run costs that entry, not the list. Why
    /// it went is kept: a subscription's lone survivor may be a placeholder.
    private static func parse(_ text: String) throws -> (servers: [XrayServer], skipped: [String]) {
        var body = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if !body.contains("://"), !body.hasPrefix("["), !body.hasPrefix("{"), let decoded = base64Decoded(body) {
            body = decoded.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        let isJSON = body.hasPrefix("[") || body.hasPrefix("{")
        let entries: [() throws -> XrayServer]
        if isJSON {
            guard let root = try? JSONSerialization.jsonObject(with: Data(body.utf8)) else { throw invalid("Некорректный JSON подписки") }
            let configs = root as? [[String: Any]] ?? (root as? [String: Any]).map { [$0] } ?? []
            entries = configs.map { config in { try server(fromConfig: config) } }
        } else {
            entries = body.components(separatedBy: .newlines).filter { $0.contains("://") }
                .map { line in { try server(fromLink: line.trimmingCharacters(in: .whitespaces)) } }
        }
        var servers: [XrayServer] = []
        var skipped: [Error] = []
        for entry in entries {
            do { servers.append(try entry()) } catch { skipped.append(error) }
        }
        guard !servers.isEmpty else {
            throw skipped.first ?? invalid(isJSON ? "В JSON-подписке нет поддерживаемых серверов" : "Не найдено ни одной ссылки на сервер")
        }
        return (servers, skipped.map { ($0 as? RouterErrorInfo)?.message ?? $0.localizedDescription })
    }

    /// A subscription's body with what its headers say: `profile-title`,
    /// `subscription-userinfo`, `profile-update-interval`, `announce`,
    /// `support-url` and `profile-web-page-url`, as Happ reads them.
    public static func subscription(body: String, headers: [String: String]) throws -> XraySubscription {
        let parsed = try parse(body)
        var result = XraySubscription(servers: parsed.servers, skipped: parsed.skipped)
        result.title = headers["profile-title"].map { text($0, limit: 40) }.flatMap { $0.isEmpty ? nil : $0 }
        result.announce = headers["announce"].map { text($0, limit: 500) }.flatMap { $0.isEmpty ? nil : $0 }
        result.supportURL = headers["support-url"].flatMap(webLink)
        result.webPageURL = headers["profile-web-page-url"].flatMap(webLink)
        if let info = headers["subscription-userinfo"] {
            var fields: [String: Int64] = [:]
            for part in info.split(separator: ";") {
                let pair = part.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                if pair.count == 2, let number = Int64(pair[1]) { fields[pair[0].lowercased()] = number }
            }
            if fields["upload"] != nil || fields["download"] != nil {
                result.usedBytes = (fields["upload"] ?? 0) + (fields["download"] ?? 0)
            }
            result.totalBytes = fields["total"]
            result.expiresAt = fields["expire"].flatMap { $0 > 0 ? Date(timeIntervalSince1970: TimeInterval($0)) : nil }
        }
        if let hours = headers["profile-update-interval"].flatMap({ Double($0.trimmingCharacters(in: .whitespaces)) }), hours > 0 {
            result.updateInterval = max(hours, 1) * 3600
        }
        return result
    }

    public static let defaultUserAgent = "VPNRouter/\(VPNRouterVersion.current)"

    /// Providers answer a client they do not know with a placeholder server, so
    /// the user may name the one they expect. It has to fit one header line.
    public static func userAgent(_ text: String) throws -> String? {
        let value = text.trimmingCharacters(in: .whitespaces)
        guard value.count <= 256, value.unicodeScalars.allSatisfy({ (0x20...0x7E).contains($0.value) }) else {
            throw invalid("User-Agent — одна строка латиницей, не длиннее 256 символов")
        }
        return value.isEmpty ? nil : value
    }

    public static func server(fromLink link: String) throws -> XrayServer {
        guard let end = link.range(of: "://") else { throw invalid("Это не ссылка на сервер") }
        let scheme = link[..<end.lowerBound].lowercased()
        switch scheme {
        case "vless", "trojan": return try vlessOrTrojan(link, scheme: scheme)
        case "vmess": return try vmess(link)
        case "ss": return try shadowsocks(link)
        case "hysteria2", "hy2": return try hysteria2(link, scheme: scheme)
        default: throw invalid("Протокол \(scheme) не поддерживается")
        }
    }

    // MARK: - Output

    /// The whole config Xray runs with: our TUN, our probe door, their server.
    public static func configuration(for server: XrayServer, interface: String, physicalInterface: String, probe: XrayProbe) throws -> String {
        guard let outbounds = try? JSONSerialization.jsonObject(with: Data(server.outbounds.utf8)) as? [[String: Any]], !outbounds.isEmpty else {
            throw invalid("Запись сервера Xray повреждена: добавьте его заново")
        }
        let config: [String: Any] = [
            // "info", not "warning": a tunnel that connects but carries nothing
            // says so only at this level, and the log is the one place to see it.
            "log": ["loglevel": "info"],
            "inbounds": [
                [
                    "tag": "tun", "protocol": "tun",
                    // Every outbound leaves on the physical interface whatever the
                    // routes say, so the tunnel can never swallow its own server.
                    "settings": ["name": interface, "mtu": 1500, "gateway": [gateway], "autoOutboundsInterface": physicalInterface] as [String: Any],
                ],
                [
                    "tag": "probe", "protocol": "socks", "listen": "127.0.0.1", "port": probe.port,
                    "settings": ["auth": "password", "accounts": [["user": probe.user, "pass": probe.password]], "udp": false] as [String: Any],
                ],
            ] as [[String: Any]],
            "outbounds": outbounds,
        ]
        return String(decoding: try JSONSerialization.data(withJSONObject: config, options: [.sortedKeys, .prettyPrinted]), as: UTF8.self)
    }

    // MARK: - Share links

    private static func vlessOrTrojan(_ text: String, scheme: String) throws -> XrayServer {
        let link = try Link(text, scheme: scheme)
        let host = try validHost(link.host)
        let port = try validPort(link.port)
        var settings: [String: Any] = ["address": host, "port": port]
        if scheme == "vless" {
            guard UUID(uuidString: link.user) != nil else { throw invalid("Некорректный UUID в ссылке VLESS") }
            settings["id"] = link.user
            settings["encryption"] = link.value("encryption") ?? "none"
            if let flow = link.value("flow") { settings["flow"] = flow }
        } else {
            guard !link.user.isEmpty else { throw invalid("В ссылке Trojan нет пароля") }
            settings["password"] = link.user
        }
        let stream = try streamSettings(link.query, host: host, defaultSecurity: scheme == "trojan" ? "tls" : "none")
        return try server(name: link.name, host: host, port: port, outbounds: [["protocol": scheme, "settings": settings, "streamSettings": stream]])
    }

    /// v2rayN's form: base64 of a JSON object with its own field names.
    private static func vmess(_ text: String) throws -> XrayServer {
        guard let decoded = base64Decoded(String(text.dropFirst("vmess://".count))),
              let object = try? JSONSerialization.jsonObject(with: Data(decoded.utf8)) as? [String: Any]
        else { throw invalid("Некорректная ссылка VMess") }
        func field(_ key: String) -> String? {
            let value = (object[key] as? String) ?? (object[key] as? NSNumber)?.stringValue
            return value?.isEmpty == false ? value : nil
        }
        let host = try validHost(field("add") ?? "")
        let port = try validPort(field("port") ?? "")
        guard let id = field("id"), UUID(uuidString: id) != nil else { throw invalid("Некорректный UUID в ссылке VMess") }
        let network = field("net") ?? "tcp"
        var query = ["type": network, "security": field("tls") == "tls" ? "tls" : "none"]
        for (key, name) in [("host", "host"), ("path", "path"), ("sni", "sni"), ("alpn", "alpn"), ("fp", "fp")] { query[key] = field(name) }
        // gRPC keeps its service name in "path" and its mode in "type".
        if network == "grpc" {
            query["serviceName"] = field("path")
            query["mode"] = field("type")
        } else {
            query["headerType"] = field("type")
        }
        let settings: [String: Any] = ["address": host, "port": port, "id": id, "security": field("scy") ?? "auto"]
        let stream = try streamSettings(query, host: host, defaultSecurity: "none")
        return try server(name: field("ps") ?? "", host: host, port: port, outbounds: [["protocol": "vmess", "settings": settings, "streamSettings": stream]])
    }

    /// SIP002 (`ss://base64(method:password)@host:port`) and the legacy form that
    /// base64-encodes the whole `method:password@host:port`.
    private static func shadowsocks(_ text: String) throws -> XrayServer {
        var body = String(text.dropFirst("ss://".count))
        var fragment = ""
        if let hash = body.firstIndex(of: "#") {
            fragment = String(body[hash...])
            body = String(body[..<hash])
        }
        if !body.contains("@"), let decoded = base64Decoded(body.components(separatedBy: "?")[0]) { body = decoded }
        let link = try Link("ss://" + body + fragment, scheme: "ss")
        guard link.query["plugin"] == nil else { throw invalid("Плагины Shadowsocks не поддерживаются") }
        let credentials = link.user.contains(":") ? link.user : base64Decoded(link.user) ?? ""
        guard let colon = credentials.firstIndex(of: ":") else { throw invalid("Некорректная ссылка Shadowsocks") }
        let method = credentials[..<colon].lowercased()
        let password = String(credentials[credentials.index(after: colon)...])
        guard shadowsocksMethods.contains(method), !password.isEmpty else { throw invalid("Шифр Shadowsocks \(method) не поддерживается") }
        let host = try validHost(link.host)
        let port = try validPort(link.port)
        let settings: [String: Any] = ["address": host, "port": port, "method": method, "password": password]
        return try server(name: link.name, host: host, port: port, outbounds: [["protocol": "shadowsocks", "settings": settings]])
    }

    private static func hysteria2(_ text: String, scheme: String) throws -> XrayServer {
        let link = try Link(text, scheme: scheme)
        let host = try validHost(link.host)
        // "443,20000-30000": the first port dials, and the lot is what udphop hops over.
        let hopping = link.port.contains { $0 == "," || $0 == "-" }
        guard link.port.allSatisfy({ $0.isNumber || $0 == "," || $0 == "-" }),
              let first = link.port.split(whereSeparator: { $0 == "," || $0 == "-" }).first
        else { throw invalid("Некорректный порт сервера") }
        let port = try validPort(String(first))
        guard !link.user.isEmpty else { throw invalid("В ссылке Hysteria2 нет пароля") }
        var masks: [[String: Any]] = []
        switch link.value("obfs") {
        case nil: break
        case "salamander":
            guard let password = link.value("obfs-password") else { throw invalid("Для salamander нужен obfs-password") }
            masks.append(["type": "salamander", "settings": ["password": password]])
        case let other?:
            throw invalid("Обфускация Hysteria2 \(other) не поддерживается")
        }
        if let hops = link.value("mport") ?? (hopping ? link.port : nil) {
            guard hops.allSatisfy({ $0.isNumber || $0 == "," || $0 == "-" }) else { throw invalid("Некорректный список портов Hysteria2") }
            // Hysteria2's own hopping: the remote port changes every interval.
            masks.append(["type": "udphop", "settings": [
                "mode": "intervalRemote", "remotePorts": hops, "interval": Int(link.value("mportHopInt") ?? "") ?? 30,
            ] as [String: Any]])
        }
        var stream: [String: Any] = [
            "network": "hysteria", "security": "tls",
            "tlsSettings": try tlsSettings(link.query, host: host),
            "hysteriaSettings": ["version": 2, "auth": link.user] as [String: Any],
        ]
        if !masks.isEmpty { stream["finalmask"] = ["udp": masks] }
        let settings: [String: Any] = ["version": 2, "address": host, "port": port]
        return try server(name: link.name, host: host, port: port, outbounds: [["protocol": "hysteria", "settings": settings, "streamSettings": stream]])
    }

    /// The transport and security of a VLESS, Trojan or VMess link, by the
    /// share-link standard's names. Anything not read here never reaches Xray.
    private static func streamSettings(_ query: [String: String], host: String, defaultSecurity: String) throws -> [String: Any] {
        func value(_ key: String) -> String? { query[key].flatMap { $0.isEmpty ? nil : $0 } }
        var stream: [String: Any] = [:]
        switch (value("type") ?? "tcp").lowercased() {
        case "tcp", "raw":
            if let header = value("headerType"), header != "none" { throw invalid("Маскировка TCP под HTTP не поддерживается") }
            stream["network"] = "raw"
        case "ws":
            stream["network"] = "ws"
            stream["wsSettings"] = pathAndHost(query)
        case "httpupgrade":
            stream["network"] = "httpupgrade"
            stream["httpupgradeSettings"] = pathAndHost(query)
        case "grpc":
            var grpc: [String: Any] = ["serviceName": value("serviceName") ?? ""]
            if value("mode") == "multi" { grpc["multiMode"] = true }
            if let authority = value("authority") { grpc["authority"] = authority }
            stream["network"] = "grpc"
            stream["grpcSettings"] = grpc
        case "xhttp", "splithttp":
            var xhttp = pathAndHost(query)
            if let mode = value("mode") { xhttp["mode"] = mode }
            if let extra = value("extra") {
                guard let object = try? JSONSerialization.jsonObject(with: Data(extra.utf8)) as? [String: Any] else {
                    throw invalid("Некорректный параметр extra у XHTTP")
                }
                xhttp["extra"] = sanitized(object)
            }
            stream["network"] = "xhttp"
            stream["xhttpSettings"] = xhttp
        case let other:
            throw invalid("Транспорт \(other) не поддерживается")
        }
        switch (value("security") ?? defaultSecurity).lowercased() {
        case "none": break
        case "tls":
            stream["security"] = "tls"
            stream["tlsSettings"] = try tlsSettings(query, host: host)
        case "reality":
            guard let publicKey = value("pbk") ?? value("password"), ["raw", "xhttp", "grpc"].contains(stream["network"] as? String ?? "") else {
                throw invalid("Для REALITY нужны pbk и транспорт tcp, xhttp или grpc")
            }
            var reality: [String: Any] = [
                "serverName": value("sni") ?? host, "fingerprint": value("fp") ?? "chrome",
                "publicKey": publicKey, "shortId": value("sid") ?? "", "spiderX": value("spx") ?? "",
            ]
            if let verify = value("pqv") { reality["mldsa65Verify"] = verify }
            stream["security"] = "reality"
            stream["realitySettings"] = reality
        case let other:
            throw invalid("Защита \(other) не поддерживается")
        }
        return stream
    }

    private static func pathAndHost(_ query: [String: String]) -> [String: Any] {
        var settings: [String: Any] = ["path": query["path"].flatMap { $0.isEmpty ? nil : $0 } ?? "/"]
        if let host = query["host"], !host.isEmpty { settings["host"] = host }
        return settings
    }

    /// Xray v26 no longer turns certificate checks off: a server that asked for
    /// that has to name its certificate instead, or it is refused here with the
    /// reason rather than failing inside Xray without one.
    private static func tlsSettings(_ query: [String: String], host: String) throws -> [String: Any] {
        func value(_ key: String) -> String? { query[key].flatMap { $0.isEmpty ? nil : $0 } }
        var tls: [String: Any] = ["serverName": value("sni") ?? value("peer") ?? host]
        if let fingerprint = value("fp") { tls["fingerprint"] = fingerprint }
        if let alpn = value("alpn") { tls["alpn"] = alpn.split(separator: ",").map(String.init) }
        if let pin = value("pcs") ?? value("pinSHA256") { tls["pinnedPeerCertSha256"] = pin }
        if let names = value("vcn") { tls["verifyPeerCertByName"] = names }
        if let ech = value("ech") { tls["echConfigList"] = ech }
        let insecure = ["1", "true"].contains(value("allowInsecure") ?? value("insecure") ?? "")
        guard !insecure || tls["pinnedPeerCertSha256"] != nil || tls["verifyPeerCertByName"] != nil else {
            throw invalid("Сервер просит не проверять сертификат, а Xray так больше не умеет: нужна ссылка с pinSHA256")
        }
        return tls
    }

    // MARK: - Full configs

    /// A full Xray config, as Happ subscriptions ship them. Only its proxy outbound
    /// and the hops it dials through survive: inbounds, routing, DNS, API and
    /// logging are ours to decide.
    private static func server(fromConfig config: [String: Any]) throws -> XrayServer {
        let outbounds = config["outbounds"] as? [[String: Any]] ?? []
        func kind(_ outbound: [String: Any]) -> String { outbound["protocol"] as? String ?? "" }
        func tag(_ outbound: [String: Any]) -> String? { outbound["tag"] as? String }
        guard let proxy = outbounds.first(where: { tag($0) == "proxy" && proxyProtocols.contains(kind($0)) })
            ?? outbounds.first(where: { proxyProtocols.contains(kind($0)) })
        else { throw invalid("В конфиге нет поддерживаемого сервера") }
        var chain = [proxy]
        while chain.count < 4, let next = dialerProxy(chain[chain.count - 1]),
              !chain.contains(where: { tag($0) == next }),
              let hop = outbounds.first(where: { tag($0) == next && hopProtocols.contains(kind($0)) }) {
            chain.append(hop)
        }
        guard !chain.contains(where: { insecure($0) }) else {
            throw invalid("Сервер просит не проверять сертификат, а Xray так больше не умеет")
        }
        var cleaned = chain.map { outbound in
            sanitized(outbound.filter { ["protocol", "tag", "settings", "streamSettings", "mux"].contains($0.key) }) as? [String: Any] ?? [:]
        }
        // A hop that was not kept must not be asked for.
        let kept = Set(cleaned.compactMap { tag($0) })
        for index in cleaned.indices {
            guard let next = dialerProxy(cleaned[index]), !kept.contains(next),
                  var stream = cleaned[index]["streamSettings"] as? [String: Any],
                  var sockopt = stream["sockopt"] as? [String: Any]
            else { continue }
            sockopt["dialerProxy"] = nil
            stream["sockopt"] = sockopt
            cleaned[index]["streamSettings"] = stream
        }
        let (host, port) = try endpoint(of: cleaned[0])
        return try server(name: config["remarks"] as? String ?? "", host: host, port: port, outbounds: cleaned)
    }

    private static func endpoint(of outbound: [String: Any]) throws -> (String, Int) {
        let settings = outbound["settings"] as? [String: Any] ?? [:]
        let target = (settings["vnext"] as? [[String: Any]])?.first ?? (settings["servers"] as? [[String: Any]])?.first ?? settings
        let port = (target["port"] as? NSNumber)?.intValue ?? Int(target["port"] as? String ?? "") ?? 0
        return (try validHost(target["address"] as? String ?? ""), try validPort(String(port)))
    }

    private static func dialerProxy(_ outbound: [String: Any]) -> String? {
        ((outbound["streamSettings"] as? [String: Any])?["sockopt"] as? [String: Any])?["dialerProxy"] as? String
    }

    /// Whether an allowInsecure: true hides in it, however deep.
    private static func insecure(_ value: Any) -> Bool {
        if let object = value as? [String: Any] {
            return object["allowInsecure"] as? Bool == true || object.values.contains { insecure($0) }
        }
        return (value as? [Any])?.contains { insecure($0) } ?? false
    }

    private static func sanitized(_ value: Any) -> Any {
        if let object = value as? [String: Any] {
            return object.filter { !forbiddenKeys.contains($0.key) && !$0.key.hasSuffix("File") }.mapValues(sanitized)
        }
        if let array = value as? [Any] { return array.map(sanitized) }
        return value
    }

    // MARK: - Pieces

    private static func server(name: String, host: String, port: Int, outbounds: [[String: Any]]) throws -> XrayServer {
        var outbounds = outbounds
        outbounds[0]["tag"] = "proxy"
        let data = try JSONSerialization.data(withJSONObject: outbounds, options: [.sortedKeys])
        let label = name.trimmingCharacters(in: .whitespacesAndNewlines)
        return XrayServer(
            name: label.isEmpty ? "\(host):\(port)" : String(label.prefix(80)),
            protocolName: outbounds[0]["protocol"] as? String ?? "",
            host: host,
            port: port,
            outbounds: String(decoding: data, as: UTF8.self)
        )
    }

    /// `scheme://user@host:port/path?query#name`, split by hand: URLComponents
    /// rejects the port lists Hysteria2 links carry ("443,20000-30000").
    private struct Link {
        var user: String
        var host: String
        var port: String
        var query: [String: String] = [:]
        var name = ""

        init(_ text: String, scheme: String) throws {
            var rest = String(text.dropFirst(scheme.count + 3))
            if let hash = rest.firstIndex(of: "#") {
                name = String(rest[rest.index(after: hash)...]).removingPercentEncoding ?? ""
                rest = String(rest[..<hash])
            }
            if let mark = rest.firstIndex(of: "?") {
                for pair in rest[rest.index(after: mark)...].split(separator: "&") {
                    let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
                    guard let key = parts.first.map(String.init), !key.isEmpty, query[key] == nil else { continue }
                    let value = parts.count > 1 ? String(parts[1]) : ""
                    query[key] = value.removingPercentEncoding ?? value
                }
                rest = String(rest[..<mark])
            }
            if let slash = rest.firstIndex(of: "/") { rest = String(rest[..<slash]) }
            guard let at = rest.lastIndex(of: "@") else { throw XrayProfileParser.invalid("В ссылке \(scheme) нет учётных данных") }
            let userPart = String(rest[..<at])
            let hostPort = String(rest[rest.index(after: at)...])
            if hostPort.hasPrefix("["), let close = hostPort.firstIndex(of: "]") {
                host = String(hostPort[hostPort.index(after: hostPort.startIndex)..<close])
                let after = hostPort[hostPort.index(after: close)...]
                guard after.hasPrefix(":") else { throw XrayProfileParser.invalid("В ссылке нет порта сервера") }
                port = String(after.dropFirst())
            } else {
                guard let colon = hostPort.lastIndex(of: ":") else { throw XrayProfileParser.invalid("В ссылке нет порта сервера") }
                host = String(hostPort[..<colon])
                port = String(hostPort[hostPort.index(after: colon)...])
            }
            user = userPart.removingPercentEncoding ?? userPart
        }

        func value(_ key: String) -> String? { query[key].flatMap { $0.isEmpty ? nil : $0 } }
    }

    private static func validHost(_ raw: String) throws -> String {
        if let address = IPAddress(raw) { return address.description }
        guard let domain = RuleSet.normalizeDomain(raw) else { throw invalid("Некорректный адрес сервера") }
        return domain
    }

    private static func validPort(_ raw: String) throws -> Int {
        guard let value = Int(raw), (1...65_535).contains(value) else { throw invalid("Некорректный порт сервера") }
        return value
    }

    /// "base64:0J/RgNC+…" or plain text, cut to what fits where it is shown.
    private static func text(_ raw: String, limit: Int) -> String {
        let text = raw.hasPrefix("base64:") ? base64Decoded(String(raw.dropFirst(7))) ?? raw : raw
        return String(text.trimmingCharacters(in: .whitespacesAndNewlines).prefix(limit))
    }

    /// Only a web page: a link a provider sends must not open anything else.
    private static func webLink(_ raw: String) -> URL? {
        guard let url = URL(string: raw.trimmingCharacters(in: .whitespaces)),
              ["http", "https"].contains(url.scheme?.lowercased() ?? ""), url.host != nil
        else { return nil }
        return url
    }

    /// Standard or URL-safe, with or without padding: subscriptions use all four.
    static func base64Decoded(_ text: String) -> String? {
        var value = text.filter { !$0.isWhitespace }
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
            .replacingOccurrences(of: "=", with: "")
        value += String(repeating: "=", count: (4 - value.count % 4) % 4)
        guard let data = Data(base64Encoded: value) else { return nil }
        return String(data: data, encoding: .utf8)
    }

    fileprivate static func invalid(_ message: String) -> RouterErrorInfo { .init(.invalidConfiguration, message) }
}
