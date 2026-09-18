import Compression
import Foundation
import Testing
@testable import VPNRouterCore
@testable import VPNRouterDaemon

@Test func domainPriorityAndNormalization() throws {
    let rules = try RuleSet(rules: [
        .init(target: .direct, kind: .domain, value: "ru"),
        .init(target: .corporate, kind: .domain, value: "corp.ru"),
        .init(target: .direct, kind: .domain, value: "пример.рф"),
    ])
    #expect(rules.classify(domain: "www.example.ru") == .direct)
    #expect(rules.classify(domain: "api.corp.ru") == .corporate)
    #expect(rules.classify(domain: "example.com") == .amneziaWG)
    #expect(RuleSet.normalizeDomain(".РФ.") == "xn--p1ai")
}

@Test func pastedProfilePicksItsEngine() {
    #expect(ExitEngine(profile: " vpn://AAAA\n") == .amneziaWG)
    #expect(ExitEngine(profile: "[Interface]\nPrivateKey = x\n[Peer]\n") == .amneziaWG)
    #expect(ExitEngine(profile: "vless://id@host:443?security=reality#NL") == .xray)
    #expect(ExitEngine(profile: "https://sub.example/abc") == .xray)
}

@Test func openVPNTriesThePickedServerFirstAndTheRestInOrder() throws {
    let profile = try OpenVPNProfileParser.parse("client\ndev tun\nremote a.example 1194 udp\nremote-random\nremote b.example 443 tcp\nremote c.example\n<ca>\nx\n</ca>\n")
    #expect(profile.remotes == [
        .init(host: "a.example", port: "1194", proto: "udp"), .init(host: "b.example", port: "443", proto: "tcp"), .init(host: "c.example"),
    ])
    #expect(profile.configuration(preferring: nil) == profile.sanitizedConfiguration)
    #expect(profile.configuration(preferring: .init(host: "gone.example")) == profile.sanitizedConfiguration)
    let picked = profile.configuration(preferring: profile.remotes[2]).components(separatedBy: "\n").filter { $0.hasPrefix("remote") }
    #expect(picked == ["remote c.example", "remote a.example 1194 udp", "remote b.example 443 tcp"])
}

@Test func aPastedLinkStandsForItsSite() {
    #expect(RoutingText.site("https://cloudflare.com/cdn-cgi/trace") == "cloudflare.com")
    #expect(RoutingText.site("site.org") == "site.org")
    #expect(RoutingText.site("10.0.0.0/8") == "10.0.0.0/8")
}

@Test func routingTextSurvivesTheClipboardAndRejectsAnythingElse() throws {
    let text = RoutingText(corporate: "corp.example.com\n10.0.0.0/8", direct: "example.com", directRU: true, directSU: false, directRF: true)
    #expect(RoutingText(exported: text.exported) == text)
    #expect(RoutingText(exported: "просто текст из буфера") == nil)
    let settings = try RoutingText(corporate: "https://site.org/path?q=1").applied(to: .init())
    #expect(settings.rules.map(\.value) == ["site.org"])
    #expect(throws: RouterErrorInfo.self) { try RoutingText(corporate: "not a site!").applied(to: .init()) }
}

@Test func nettopRowsYieldOutboundFlowsAndTheirProcess() {
    #expect(ObservedFlow.parse("tcp4 192.168.1.204:64917<->17.57.146.140:5223,en0,Established,")
        == .init(proto: "tcp", address: "17.57.146.140", port: "5223", interface: "en0"))
    #expect(ObservedFlow.parse("udp6 fd00::2.5353<->2a00:1450::1.443,utun8,,")
        == .init(proto: "udp", address: "2a00:1450::1", port: "443", interface: "utun8"))
    #expect(ObservedFlow.parse("tcp4 *:5959<->*:*,,Listen,") == nil)
    #expect(ObservedFlow.parse("udp4 192.168.1.2:62904<->127.0.0.1:53,lo0,Loop,") == nil)
    #expect(ObservedFlow.parse("udp6 fe80::1%awdl0.53734<->fe80::cc18:92ff:fea5:72a4%awdl0.53735,awdl0,,") == nil)
    #expect(ObservedFlow.parse("tcp4 169.254.1.2:5000<->169.254.7.8:7000,en0,Established,") == nil)
    #expect(ObservedFlow.process("Google Chrome He.812,,,").map { "\($0.name).\($0.pid)" } == "Google Chrome He.812")
    #expect(ObservedFlow.process(",interface,state,") == nil)
    #expect(PingOutput.averageMilliseconds("round-trip min/avg/max/stddev = 0.081/0.133/0.168/0.037 ms") == 0.133)
    #expect(PingOutput.averageMilliseconds("3 packets transmitted, 0 packets received, 100.0% packet loss") == nil)
}

@Test func liveLogHandsOutOnlyNewLinesAndEverythingAfterADaemonRestart() {
    let path = NSTemporaryDirectory() + "vpnrouter-live-\(UUID().uuidString).log"
    defer { try? FileManager.default.removeItem(atPath: path) }
    let log = TunnelLog(path: path)
    log.write("router", "one")
    let first = log.lines(after: 0)
    log.write("router", "two")
    let second = log.lines(after: first.next)
    #expect(first.lines.count == 1 && first.lines[0].hasSuffix("[router] one"))
    #expect(second.lines.count == 1 && second.lines[0].hasSuffix("[router] two"))
    #expect(log.lines(after: second.next).lines.isEmpty)
    #expect(log.lines(after: 99).lines.count == 2)
}

@Test func cidrLongestMatchAndCorporateTie() throws {
    let rules = try RuleSet(rules: [
        .init(target: .direct, kind: .cidr, value: "10.0.0.0/8"),
        .init(target: .corporate, kind: .cidr, value: "10.20.0.0/16"),
        .init(target: .corporate, kind: .cidr, value: "172.16.0.0/12"),
        .init(target: .direct, kind: .cidr, value: "172.16.10.0/24"),
        .init(target: .direct, kind: .cidr, value: "2001:db8::/32"),
    ])
    #expect(rules.classify(ip: "10.1.2.3") == .direct)
    #expect(rules.classify(ip: "10.20.2.3") == .corporate)
    #expect(rules.classify(ip: "172.16.10.1") == .corporate)
    #expect(rules.classify(ip: "2001:db8::1") == .direct)
    #expect(CIDR("10.20.99.7/16")?.description == "10.20.0.0/16")
    #expect(CIDR("2001:db8:1::abcd/48")?.description == "2001:db8:1::/48")
}

@Test func openVPNRejectsTapAndExtractsRoutes() throws {
    #expect(throws: RouterErrorInfo.self) {
        try OpenVPNProfileParser.parse("client\ndev tap\n<ca>\nx\n</ca>\n")
    }
    let profile = try OpenVPNProfileParser.parse("""
        client
        dev tun
        auth-user-pass
        route 10.20.0.0 255.255.0.0
        redirect-gateway def1
        up /trusted/script
        <ca>
        test
        </ca>
        """)
    #expect(profile.requiresCredentials)
    #expect(profile.staticRoutes == ["10.20.0.0/16"])
    #expect(profile.dangerousDirectives == ["up /trusted/script"])
    #expect(!profile.sanitizedConfiguration.contains("redirect-gateway def1"))
    let trusted = try OpenVPNProfileParser.parse("client\ndev tun\nup /trusted/script\n", allowUnsafe: true)
    #expect(trusted.sanitizedConfiguration.contains("script-security 2"))
    #expect(throws: RouterErrorInfo.self) {
        try OpenVPNProfileParser.parse("client\ndev tun\nconfig /tmp/other.conf\n")
    }
    #expect(throws: RouterErrorInfo.self) {
        try OpenVPNProfileParser.parse("client\ndev tun\nroute not-an-ip 255.255.255.0\n")
    }
    let prefixed = try OpenVPNProfileParser.parse("client\ndev tun\n--up /trusted/script\n")
    #expect(prefixed.dangerousDirectives == ["--up /trusted/script"])
    let linux = try OpenVPNProfileParser.parse("client\ndev tun\nscript-security 2\nup /etc/openvpn/update-resolv-conf\ndown /etc/openvpn/update-resolv-conf\n")
    #expect(linux.dangerousDirectives.isEmpty)
    #expect(!linux.sanitizedConfiguration.contains("update-resolv-conf"))
}

@Test func pushedOpenVPNOptionsDiscardInvalidAddresses() {
    let pushed = OpenVPNProfileParser.pushedOptions(from: ">PUSH:Received control message: 'PUSH_REPLY,route 10.20.1.7 255.255.0.0,route injected 255.255.255.0,route-ipv6 2001:db8::1/48,dhcp-option DNS 10.0.0.53,dhcp-option DNS invalid'")
    #expect(pushed.routes == ["10.20.0.0/16", "2001:db8::/48"])
    #expect(pushed.dns == ["10.0.0.53"])
}

@Test func amneziaRejectsScriptsAndMultiplePeers() {
    #expect(throws: RouterErrorInfo.self) {
        try AmneziaWGProfileParser.parse("""
            [Interface]
            PrivateKey = secret
            Address = 10.0.0.2/32
            PostUp = touch /tmp/owned
            [Peer]
            PublicKey = peer
            Endpoint = vpn.example:51820
            AllowedIPs = 0.0.0.0/0
            """)
    }
}

@Test func amneziaParserProducesSetConf() throws {
    let profile = try AmneziaWGProfileParser.parse("""
        [Interface]
        PrivateKey = secret
        Address = 10.0.0.2/32, fd00::2/128
        DNS = 1.1.1.1
        Jc = 4

        [Peer]
        PublicKey = peer
        Endpoint = vpn.example:51820
        AllowedIPs = 0.0.0.0/0, ::/0
        """)
    #expect(profile.endpoint == "vpn.example:51820")
    #expect(profile.supportsIPv6)
    #expect(profile.setConf.contains("PersistentKeepalive = 25"))
    #expect(!profile.setConf.contains("Address ="))
}

/// Mirrors Qt's `qCompress`: 4-byte big-endian uncompressed size, then a zlib
/// stream (the Adler-32 trailer, which nothing reads, is left out), base64url
/// with no padding.
private func makeVpnLink(_ json: [String: Any]) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: json)
    let source = [UInt8](data)
    var compressed = [UInt8](repeating: 0, count: source.count + 64)
    let compressedCount = compressed.withUnsafeMutableBufferPointer { dst in
        source.withUnsafeBufferPointer { src in
            compression_encode_buffer(dst.baseAddress!, dst.count, src.baseAddress!, src.count, nil, COMPRESSION_ZLIB)
        }
    }
    var blob = Data()
    var size = UInt32(source.count).bigEndian
    withUnsafeBytes(of: &size) { blob.append(contentsOf: $0) }
    blob.append(contentsOf: [0x78, 0xDA])
    blob.append(contentsOf: compressed[0..<compressedCount])
    let base64 = blob.base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
    return "vpn://" + base64
}

private let testAmneziaNativeConfig = """
    [Interface]
    Address = 10.8.1.2/32
    DNS = 1.1.1.1, 1.0.0.1
    PrivateKey = client-priv
    Jc = 4

    [Peer]
    PublicKey = server-pub
    PresharedKey = psk
    AllowedIPs = 0.0.0.0/0, ::/0
    Endpoint = vpn.example:51820
    PersistentKeepalive = 25
    """

/// testAmneziaNativeConfig in an "amnezia-awg2" container with mtu "1376",
/// packed by Python's zlib the way Qt packs it: the helper above shares the
/// decoder's framework, so only this catches a mismatch with the real format.
private let qtPackedAmneziaLink = "vpn://AAACXnjahZHBTsMwDIbve4oq565ruxWmShwQcBiTpkoc1wlljcci0jRK0g6Y9u44CUIrF5IenP_7nbj2eRLhIk0nLeUStCFltPWaW-ffaOxCE6GthC9Op_T0lpN4bEQNLeNsDwQ19hWvOXBnIOeahEONp5psV9KCPtAGdnUt7xnTYEx0F2VpskyyJJ_Nc9QfNy9OS_yOMUhxZwgqzQdqYQ2fyBvBQdqpQg3Rc4PSAgP8thWAdg9U_V7wJtgN6AH0VPV7fxGYI9XAAlPm3ZUjRHcCtqpcRal_NJ2lcVSWsxTxk2Sq49IiHJRM4IO2SkBZZMvc4Qpby43FktYAigo-ADrzoiYx_vixM3ZDWwhtuMoPWHXaOlQUi3zhhNb2wZrNb29qcvnTf99ql-R67JPIiF8m42gX0gmDA-2FffhnzIRJkzn2M4MrOQ-ynwiZXL4BtXSmTQ"

private func makeAmneziaShareLink(container: String = "amnezia-awg", protoKey: String = "awg", lastConfig: [String: Any]? = nil) throws -> String {
    let lastConfig = lastConfig ?? ["config": testAmneziaNativeConfig, "hostName": "vpn.example", "port": 51820]
    let lastConfigString = String(data: try JSONSerialization.data(withJSONObject: lastConfig), encoding: .utf8)!
    return try makeVpnLink([
        "containers": [["container": container, protoKey: ["last_config": lastConfigString]]],
        "defaultContainer": container,
        "dns1": "1.1.1.1",
    ])
}

@Test func amneziaVpnLinkUnpacksToTheEmbeddedNativeConfig() throws {
    // The MTU Amnezia keeps beside the text comes along into [Interface].
    let unpacked = try AmneziaWGProfileParser.nativeConfig(fromVpnLink: qtPackedAmneziaLink)
    #expect(unpacked == testAmneziaNativeConfig.replacingOccurrences(of: "[Interface]", with: "[Interface]\nMTU = 1376"))
    let profile = try AmneziaWGProfileParser.parse(unpacked)
    #expect(profile.endpoint == "vpn.example:51820")
    #expect(profile.dnsServers == ["1.1.1.1", "1.0.0.1"])
    #expect(profile.mtu == 1376)

    #expect(try AmneziaWGProfileParser.nativeConfig(fromVpnLink: makeAmneziaShareLink()) == testAmneziaNativeConfig)
    // A plain WireGuard container (no AmneziaWG obfuscation) is accepted too.
    let wgLink = try makeAmneziaShareLink(container: "amnezia-wireguard", protoKey: "wireguard")
    #expect(try AmneziaWGProfileParser.nativeConfig(fromVpnLink: wgLink) == testAmneziaNativeConfig)

    // Amnezia keeps the template's DNS placeholders and the servers at the top level.
    let templated = testAmneziaNativeConfig.replacingOccurrences(of: "DNS = 1.1.1.1, 1.0.0.1", with: "DNS = $PRIMARY_DNS, $SECONDARY_DNS")
    let templatedLink = try makeVpnLink([
        "containers": [["container": "amnezia-awg", "awg": ["last_config": String(data: try JSONSerialization.data(withJSONObject: ["config": templated]), encoding: .utf8)!]]],
        "dns1": "172.16.0.53",
    ])
    let filled = try AmneziaWGProfileParser.parse(AmneziaWGProfileParser.nativeConfig(fromVpnLink: templatedLink))
    #expect(filled.dnsServers == ["172.16.0.53", "1.0.0.1"])
}

@Test func amneziaVpnLinkRejectsWhatItCannotUnpack() throws {
    #expect(throws: RouterErrorInfo.self) { try AmneziaWGProfileParser.nativeConfig(fromVpnLink: "not-a-link") }
    // A 4 GB size in the header must fail before anything is allocated.
    #expect(throws: RouterErrorInfo.self) {
        try AmneziaWGProfileParser.nativeConfig(fromVpnLink: "vpn://" + Data([0xFF, 0xFF, 0xFF, 0xFF, 0x78, 0xDA, 0x03, 0x00]).base64EncodedString())
    }
    #expect(throws: RouterErrorInfo.self) { try AmneziaWGProfileParser.nativeConfig(fromVpnLink: "vpn://not-valid-base64!!!") }
    #expect(throws: RouterErrorInfo.self) { try AmneziaWGProfileParser.nativeConfig(fromVpnLink: "vpn://" + Data("garbage".utf8).base64EncodedString()) }
    #expect(throws: RouterErrorInfo.self) { try AmneziaWGProfileParser.nativeConfig(fromVpnLink: makeVpnLink(["hostName": "vpn.example"])) }
    #expect(throws: RouterErrorInfo.self) { try AmneziaWGProfileParser.nativeConfig(fromVpnLink: makeVpnLink(["containers": [["container": "amnezia-openvpn"]]])) }
    #expect(throws: RouterErrorInfo.self) { try AmneziaWGProfileParser.nativeConfig(fromVpnLink: makeAmneziaShareLink(lastConfig: ["hostName": "vpn.example"])) }
}

@Test func dnsParsesCompressedARecord() throws {
    let packet: [UInt8] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x63, 0x6f, 0x72, 0x70, 0x02, 0x72, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        10, 20, 30, 40,
    ]
    let message = try DNSMessage.parse(Data(packet))
    #expect(message.questions == [.init(name: "corp.ru", type: 1)])
    #expect(message.addresses == [.init(name: "corp.ru", address: "10.20.30.40", ttl: 60)])
    #expect(message.cnames.isEmpty)
}

@Test func dnsFollowsCNAMEAndUsesShortestTTL() throws {
    let packet: [UInt8] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
        0x03, 0x77, 0x77, 0x77, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
        0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1e, 0x00, 0x08,
        0x05, 0x61, 0x6c, 0x69, 0x61, 0x73, 0xc0, 0x10,
        0x05, 0x61, 0x6c, 0x69, 0x61, 0x73, 0xc0, 0x10,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        203, 0, 113, 8,
    ]
    let message = try DNSMessage.parse(Data(packet))
    #expect(message.cnames == [.init(name: "www.example.com", canonicalName: "alias.example.com", ttl: 30)])
    #expect(message.addresses == [.init(name: "alias.example.com", address: "203.0.113.8", ttl: 30)])
}

@Test func firewallIsFailClosedPerClass() throws {
    let policy = try FirewallPolicyRenderer.render(.init(
        physicalInterface: "en0",
        openVPNInterface: "utun4",
        amneziaWGInterface: nil,
        corporate: ["10.20.0.0/16"],
        direct: ["203.0.113.2"],
        control: ["1.1.1.1"],
        lan: ["192.168.1.0/24"]
    ))
    #expect(policy.contains("pass out quick on utun4 to { <corp4>, <corp6> }"))
    #expect(policy.contains("block drop out quick to { <corp4>, <corp6> }"))
    #expect(!policy.contains("pass out quick on utun5 all"))
    #expect(!policy.contains("pass out quick on en0 all"))
    #expect(policy.hasSuffix("block drop out quick all\n"))
    // OpenVPN alone: corporate stays fail-closed, the rest goes out directly.
    let openVPNOnly = try FirewallPolicyRenderer.render(.init(physicalInterface: "en0", openVPNInterface: "utun4", directByDefault: true))
    #expect(openVPNOnly.contains("block drop out quick to { <corp4>, <corp6> }"))
    #expect(openVPNOnly.hasSuffix("pass out quick on en0 all no state\nblock drop out quick all\n"))
}

@Test func macOSAcceptsGeneratedPFSyntax() throws {
    let policy = try FirewallPolicyRenderer.render(.init(
        physicalInterface: "en0",
        openVPNInterface: "utun4",
        amneziaWGInterface: "utun5",
        corporate: ["10.20.0.0/16", "2001:db8::/32"],
        direct: ["203.0.113.2", "2001:db8:1::/48"],
        control: ["1.1.1.1"],
        lan: ["192.168.1.0/24", "fe80::/10"],
        directByDefault: true
    ))
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("commutator-\(UUID().uuidString).pf")
    try policy.write(to: url, atomically: true, encoding: .utf8)
    defer { try? FileManager.default.removeItem(at: url) }
    let process = Process()
    let error = Pipe()
    process.executableURL = URL(fileURLWithPath: "/sbin/pfctl")
    process.arguments = ["-nf", url.path]
    process.standardError = error
    try process.run()
    process.waitUntilExit()
    let message = String(decoding: error.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
    #expect(process.terminationStatus == 0, "PF syntax error: \(message)")
}

@Test func dnsRejectsPointerLoop() {
    let packet: [UInt8] = [
        0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0,
        0xc0, 0x0c, 0, 1, 0, 1,
    ]
    #expect(throws: RouterErrorInfo.self) { try DNSMessage.parse(Data(packet)) }
}

@Test func dnsAcceptsDuplicateQuestionsWithoutCrashing() throws {
    let packet = Data([
        0, 1, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0,
        1, 97, 0, 0, 1, 0, 1,
        1, 97, 0, 0, 1, 0, 1,
    ])
    let message = try DNSMessage.parse(packet)
    #expect(message.questions.count == 2)
}

@Test func firewallRejectsUntrustedTableValues() {
    #expect(throws: RouterErrorInfo.self) {
        try FirewallPolicyRenderer.render(.init(
            physicalInterface: "en0",
            corporate: ["10.0.0.0/8 } pass out all"]
        ))
    }
}

@Test func routeReconcileRollsBackAfterCommandFailure() throws {
    let recorder = Recorder()
    let runner = recordingRunner(recorder) { count, _ in
        count == 2 ? .init(status: 1, stdout: "", stderr: "injected failure") : nil
    }
    let controller = RouteController(runner: runner)
    #expect(throws: RouterErrorInfo.self) {
        try controller.reconcile(directPolicy(["203.0.113.1", "203.0.113.2"]))
    }
    #expect(recorder.joined.count == 3)
    #expect(recorder.joined.last?.contains(" delete ") == true)
}

@Test func protectionStateRequiresBothHealthyInterfaces() {
    let connecting = TunnelStatus(phase: .connecting)
    let open = TunnelStatus(phase: .connected, interfaceName: "utun4")
    let awg = TunnelStatus(phase: .connected, interfaceName: "utun5")
    #expect(ProtectionState.evaluate(desiredEnabled: false, openVPN: open, amneziaWG: awg) == .off)
    #expect(ProtectionState.evaluate(desiredEnabled: true, openVPN: connecting, amneziaWG: connecting) == .starting)
    #expect(ProtectionState.evaluate(desiredEnabled: true, openVPN: open, amneziaWG: connecting) == .starting)
    #expect(ProtectionState.evaluate(desiredEnabled: true, openVPN: open, amneziaWG: nil) == .protected)
    #expect(ProtectionState.evaluate(desiredEnabled: true, openVPN: nil, amneziaWG: .init(phase: .error)) == .degraded)
    #expect(ProtectionState.evaluate(desiredEnabled: true, openVPN: open, amneziaWG: awg) == .protected)
    #expect(ProtectionState.evaluate(desiredEnabled: true, openVPN: open, amneziaWG: .init(phase: .error)) == .degraded)
    #expect(ProtectionState.evaluate(desiredEnabled: true, openVPN: .init(phase: .connected), amneziaWG: awg) == .degraded)
}

@Test func routerErrorExposesItsMessage() {
    let error = RouterErrorInfo(.helperUnavailable, "Понятная причина")
    #expect(error.localizedDescription == "Понятная причина")
}

@Test func launchAtLoginIsOptInByDefault() {
    #expect(RouterSettings().launchAtLogin == false)
}

@Test func trafficRecordingIsOptInEvenForSettingsSavedBeforeIt() throws {
    #expect(RouterSettings().watchTraffic == false)
    #expect(try IPCCodec.decoder.decode(RouterSettings.self, from: Data("{}".utf8)).watchTraffic == false)
}

@Test func killSwitchBlocksTheRestUntilAmneziaWGIsUp() throws {
    var settings = try IPCCodec.decoder.decode(RouterSettings.self, from: Data("{}".utf8))
    #expect(settings.killSwitch)
    #expect(!settings.directByDefault(amneziaWGUp: false))
    settings.killSwitch = false
    #expect(settings.directByDefault(amneziaWGUp: false))
    #expect(!settings.directByDefault(amneziaWGUp: true))
    settings.useAmneziaWG = false
    #expect(settings.directByDefault(amneziaWGUp: true))
}

private func recordingRunner(_ recorder: Recorder, fail: @escaping @Sendable (Int, [String]) -> CommandResult?) -> CommandRunner {
    CommandRunner { executable, arguments in
        let count = recorder.append([executable] + arguments)
        return fail(count, arguments) ?? .init(status: 0, stdout: "", stderr: "")
    }
}

final class Recorder: @unchecked Sendable {
    private let lock = NSLock()
    private(set) var commands: [[String]] = []
    func append(_ value: [String]) -> Int {
        lock.lock(); defer { lock.unlock() }
        commands.append(value)
        return commands.count
    }
    var joined: [String] { commands.map { $0.joined(separator: " ") } }
}

private func directPolicy(_ addresses: Set<String>) -> PolicyState {
    var policy = PolicyState(snapshot: .init(
        physicalInterface: "en0",
        ipv4Gateway: "192.168.1.1",
        ipv6Gateway: nil,
        dnsServers: [],
        lanNetworks: ["192.168.1.0/24"]
    ))
    policy.direct = addresses
    return policy
}

@Test func routeAddAcceptsAnExistingRoute() throws {
    let recorder = Recorder()
    // A route left behind by a crashed run is already the state we asked for.
    let runner = recordingRunner(recorder) { _, arguments in
        arguments.contains("add") ? .init(status: 1, stdout: "", stderr: "route: writing to routing socket: File exists") : nil
    }
    let controller = RouteController(runner: runner)
    try controller.reconcile(directPolicy(["203.0.113.1", "203.0.113.2"]))
    #expect(recorder.commands.count == 2)
}

@Test func routeRemovalOfAMissingRouteIsNotAFailure() throws {
    let recorder = Recorder()
    // The kernel drops a tunnel's routes with its interface, so by the time we
    // reconcile they are already gone — that is success, not a routing failure.
    let runner = recordingRunner(recorder) { _, arguments in
        arguments.contains("delete") ? .init(status: 1, stdout: "", stderr: "route: not in table") : nil
    }
    let controller = RouteController(runner: runner)
    try controller.reconcile(directPolicy(["203.0.113.1"]))
    try controller.reconcile(directPolicy([]))
    #expect(recorder.joined.filter { $0.contains(" delete ") }.count == 1)
}

@Test func identicalNetworkStateComparesEqual() {
    let snapshot = NetworkSnapshot(
        physicalInterface: "en0", ipv4Gateway: "192.168.1.1", ipv6Gateway: nil,
        dnsServers: ["192.168.1.1"], lanNetworks: ["192.168.1.0/24"]
    )
    var other = snapshot
    #expect(snapshot == other)
    other = .init(
        physicalInterface: "en1", ipv4Gateway: "192.168.1.1", ipv6Gateway: nil,
        dnsServers: ["192.168.1.1"], lanNetworks: ["192.168.1.0/24"]
    )
    #expect(snapshot != other)
    #expect(directPolicy(["203.0.113.1"]) == directPolicy(["203.0.113.1"]))
    #expect(directPolicy(["203.0.113.1"]) != directPolicy(["203.0.113.2"]))
}

@Test func dnsCanonicalisesIPv6Answers() throws {
    var packet: [UInt8] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x63, 0x6f, 0x72, 0x70, 0x02, 0x72, 0x75, 0x00, 0x00, 0x1c, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10,
    ]
    packet += [0x20, 0x01, 0x0d, 0xb8] + [UInt8](repeating: 0, count: 11) + [0x01]
    let message = try DNSMessage.parse(Data(packet))
    #expect(message.addresses == [.init(name: "corp.ru", address: "2001:db8::1", ttl: 60)])
}

@Test func serverFailureAnswersTheOriginalQuestion() throws {
    let query = Data([
        0x12, 0x34, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x04, 0x63, 0x6f, 0x72, 0x70, 0x02, 0x72, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01,
    ])
    let failure = DNSMessage.serverFailure(for: query)
    #expect(failure[0] == 0x12 && failure[1] == 0x34)   // same transaction id
    #expect(failure[2] & 0x80 == 0x80)                  // it is a response
    #expect(failure[2] & 0x01 == 0x01)                  // recursion-desired kept
    #expect(failure[3] & 0x0f == 0x02)                  // SERVFAIL
    let parsed = try DNSMessage.parse(failure)
    #expect(parsed.questions == [.init(name: "corp.ru", type: 1)])
    #expect(parsed.addresses.isEmpty)
    #expect(DNSMessage.serverFailure(for: Data([0x12, 0x34])).isEmpty)
}

@Test func upstreamTableRoutesEachClassAndRefusesWhenUnreachable() throws {
    let rules = try RuleSet(rules: [
        .init(target: .direct, kind: .domain, value: "ru"),
        .init(target: .corporate, kind: .domain, value: "corp.example"),
    ])
    let table = UpstreamTable()
    #expect(table.servers(for: "example.com").isEmpty) // nothing configured yet

    table.update(.init(
        ruleSet: rules,
        corporate: ["10.0.0.53"],
        direct: ["192.168.1.1", "192.168.1.2"],
        amneziaWG: ["10.8.0.1"]
    ))
    #expect(table.servers(for: "api.corp.example") == ["10.0.0.53"])
    // The whole list is handed over: the proxy falls over to the second server
    // instead of losing the class to one dead resolver.
    #expect(table.servers(for: "www.example.ru") == ["192.168.1.1", "192.168.1.2"])
    #expect(table.servers(for: "example.com") == ["10.8.0.1"])
    #expect(table.tracksAddresses(for: "www.example.ru"))
    #expect(!table.tracksAddresses(for: "example.com"))

    // AmneziaWG down: its resolver lives behind the tunnel, so we refuse rather
    // than quietly leak the name to the network's DNS.
    table.update(.init(ruleSet: rules, corporate: ["10.0.0.53"], direct: ["192.168.1.1"], amneziaWG: []))
    #expect(table.servers(for: "example.com").isEmpty)
    #expect(table.servers(for: "www.example.ru") == ["192.168.1.1"])
}

@Test func amneziaKeepsMTUAndRejectsAnImpossibleOne() throws {
    let profile = try AmneziaWGProfileParser.parse("""
        [Interface]
        PrivateKey = SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkMTI=
        Address = 10.8.1.8/32
        MTU = 1280

        [Peer]
        PublicKey = cGVlcmtleXBlZXJrZXlwZWVya2V5cGVlcmtleWFiY2Q=
        Endpoint = vpn.example:51820
        AllowedIPs = 0.0.0.0/0
        """)
    #expect(profile.mtu == 1280)
    // MTU is applied with ifconfig, so a nonsense value must fail the import and
    // not the tunnel startup.
    #expect(throws: RouterErrorInfo.self) {
        try AmneziaWGProfileParser.parse("""
            [Interface]
            PrivateKey = SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkMTI=
            Address = 10.8.1.8/32
            MTU = 68

            [Peer]
            PublicKey = cGVlcmtleXBlZXJrZXlwZWVya2V5cGVlcmtleWFiY2Q=
            Endpoint = vpn.example:51820
            AllowedIPs = 0.0.0.0/0
            """)
    }
}

@Test func networkServiceNameIsFoundForABSDInterface() {
    let listing = """
        An asterisk (*) denotes that a network service is disabled.
        (1) Wi-Fi
        (Hardware Port: Wi-Fi, Device: en0)

        (2) Thunderbolt Bridge
        (Hardware Port: Thunderbolt Bridge, Device: bridge0)

        """
    #expect(ResolverController.serviceName(forInterface: "en0", in: listing) == "Wi-Fi")
    #expect(ResolverController.serviceName(forInterface: "bridge0", in: listing) == "Thunderbolt Bridge")
    #expect(ResolverController.serviceName(forInterface: "en9", in: listing) == nil)
}

@Test func managementLinesSurviveCRLFAndArriveOneAtATime() {
    // Exactly what OpenVPN sends: CRLF, which Swift counts as one Character.
    var buffer = ">INFO:OpenVPN Management Interface Version 5\r\n>HOLD:Waiting for hold release:0\r\n>PASS"
    #expect(LineSplitter.take(from: &buffer) == [
        ">INFO:OpenVPN Management Interface Version 5",
        ">HOLD:Waiting for hold release:0",
    ])
    #expect(buffer == ">PASS")

    buffer += "WORD:Need 'Private Key' password\r\n"
    let rest = LineSplitter.take(from: &buffer)
    #expect(rest == [">PASSWORD:Need 'Private Key' password"])
    #expect(buffer.isEmpty)
    #expect(TunnelSupervisor.realm(in: rest[0]) == "Private Key")
    #expect(TunnelSupervisor.realm(in: ">PASSWORD:Need 'Auth' username/password") == "Auth")
}

@Test func storedPasswordSurvivesAReimportButNotAReplacement() {
    let stored = ProfilePayload(kind: .openVPN, configuration: "old", username: "u", password: "12345678")
    let reimport = ProfilePayload(kind: .openVPN, configuration: "new")
    #expect(RouterCoordinator.carryingCredentials(reimport, from: stored).password == "12345678")
    let replaced = ProfilePayload(kind: .openVPN, configuration: "old", password: "changed")
    #expect(RouterCoordinator.carryingCredentials(replaced, from: stored).password == "changed")
    // AmneziaWG has no password; the OpenVPN one must not leak into it.
    let awg = ProfilePayload(kind: .amneziaWG, configuration: "awg")
    #expect(RouterCoordinator.carryingCredentials(awg, from: stored).password == nil)
}

@Test func tunnelLogRedactsCredentialsAndKeepsTheNewerHalf() throws {
    let path = NSTemporaryDirectory() + "commutator-test-\(UUID().uuidString).log"
    defer { try? FileManager.default.removeItem(atPath: path) }
    let log = TunnelLog(path: path, limit: 4_000)
    log.write("mgmt", ">PASSWORD:Need 'Auth' username/password")
    log.write("mgmt", "password \"Auth\" \"s3cret\"")
    let head = try String(contentsOfFile: path, encoding: .utf8)
    #expect(head.contains(">PASSWORD:Need"))
    #expect(!head.contains("s3cret"))

    for index in 0..<400 { log.write("openvpn", "строка \(index) " + String(repeating: "x", count: 40)) }
    let trimmed = try String(contentsOfFile: path, encoding: .utf8)
    #expect(trimmed.count < 4_000)
    #expect(trimmed.contains("строка 399"))
    #expect(!trimmed.contains("строка 0 "))
}

@Test func networksetupFailureIsNoticedEvenWithAZeroStatus() {
    let ok = CommandResult(status: 0, stdout: "", stderr: "")
    let printedError = CommandResult(status: 0, stdout: "** Error: The parameters were not valid.\n", stderr: "")
    let nonZero = CommandResult(status: 1, stdout: "", stderr: "")
    #expect(ResolverController.failed(ok) == false)
    #expect(ResolverController.failed(printedError))
    #expect(ResolverController.failed(nonZero))
}

@Test func dnsBackupKeepsAScopedServerAndDropsThePlaceholderLine() {
    let listing = "There aren't any DNS Servers set on Wi-Fi.\n"
    #expect(ResolverController.parseServers(listing).isEmpty)
    #expect(ResolverController.parseServers("1.1.1.1\nfe80::1%en0\n") == ["1.1.1.1", "fe80::1%en0"])
}

@Test func amneziaAcceptsBlankObfuscationKnobs() throws {
    // Реальный профиль Amnezia: I2..I5 пустые, а у I1 значение с пробелами.
    let profile = try AmneziaWGProfileParser.parse("""
        [Interface]
        Address = 10.8.1.8/32
        DNS = 77.88.8.8, 8.8.8.8
        PrivateKey = SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkMTI=
        Jc = 4
        Jmin = 10
        Jmax = 50
        S1 = 122
        S2 = 85
        S3 = 46
        S4 = 8
        H1 = 1396604382-1645267900
        H2 = 1787931040-2102523397
        H3 = 2141322481-2145378919
        H4 = 2147100386-2147331421
        I1 = <r 2><b 0x858000010001000000000669636c6f7564>
        I2 =
        I3 =
        I4 =
        I5 =

        [Peer]
        PublicKey = cGVlcmtleXBlZXJrZXlwZWVya2V5cGVlcmtleWFiY2Q=
        Endpoint = vpn.example:51820
        AllowedIPs = 0.0.0.0/0
        """)
    #expect(profile.dnsServers == ["77.88.8.8", "8.8.8.8"])
    #expect(profile.setConf.contains("I1 = <r 2><b 0x858000010001000000000669636c6f7564>"))
    #expect(profile.setConf.contains("S4 = 8"))
    // Пустая настройка ничего не задаёт, а "I2 =" awg setconf не принимает.
    #expect(!profile.setConf.contains("I2"))
    #expect(!profile.setConf.contains("I5"))
    // Padding у base64-ключа должен уцелеть.
    #expect(profile.setConf.contains("PrivateKey = SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkMTI="))
}

@Test func amneziaRejectsALineWithoutASeparator() {
    #expect(throws: RouterErrorInfo.self) {
        try AmneziaWGProfileParser.parse("""
            [Interface]
            PrivateKey = secret
            Address = 10.0.0.2/32
            ThisLineHasNoEquals
            [Peer]
            PublicKey = peer
            Endpoint = vpn.example:51820
            AllowedIPs = 0.0.0.0/0
            """)
    }
}

@Test func amneziaNamesWhatIsMissingFromAShortPeer() {
    // Профиль разбирается, но peer без AllowedIPs/Endpoint отвергается по существу,
    // а не жалобой на синтаксис пустых I2..I5.
    let short = """
        [Interface]
        Address = 10.8.1.8/32
        PrivateKey = SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkMTI=
        I2 =

        [Peer]
        PublicKey = cGVlcmtleXBlZXJrZXlwZWVya2V5cGVlcmtleWFiY2Q=
        """
    #expect {
        try AmneziaWGProfileParser.parse(short)
    } throws: { error in
        (error as? RouterErrorInfo)?.message == "Ровно один AWG peer должен содержать 0.0.0.0/0"
    }
}

@Test func ourOwnResolverChangesDoNotLookLikeANetworkChange() {
    let captured = NetworkSnapshot(
        physicalInterface: "en0", ipv4Gateway: "192.168.1.1", ipv6Gateway: nil,
        dnsServers: ["10.0.0.53"], lanNetworks: ["192.168.1.0/24"]
    )
    // scutil --dns also lists /etc/resolver entries and the system resolver we
    // repoint at the proxy, so a re-capture after startup sees 127.0.0.1 appear.
    let afterOurOwnSetup = NetworkSnapshot(
        physicalInterface: "en0", ipv4Gateway: "192.168.1.1", ipv6Gateway: nil,
        dnsServers: ["127.0.0.1", "10.0.0.53"], lanNetworks: ["192.168.1.0/24"]
    )
    #expect(captured != afterOurOwnSetup)
    #expect(captured.routingIdentity == afterOurOwnSetup.routingIdentity, "иначе daemon перезапускает себя по кругу")

    let movedToAnotherWiFi = NetworkSnapshot(
        physicalInterface: "en0", ipv4Gateway: "10.0.0.1", ipv6Gateway: nil,
        dnsServers: ["10.0.0.53"], lanNetworks: ["10.0.0.0/24"]
    )
    #expect(captured.routingIdentity != movedToAnotherWiFi.routingIdentity)

    let switchedInterface = NetworkSnapshot(
        physicalInterface: "en1", ipv4Gateway: "192.168.1.1", ipv6Gateway: nil,
        dnsServers: ["10.0.0.53"], lanNetworks: ["192.168.1.0/24"]
    )
    #expect(captured.routingIdentity != switchedInterface.routingIdentity)
}

@Test func amneziaCollectsAllowedIPsAcrossLines() throws {
    let profile = try AmneziaWGProfileParser.parse("""
        [Interface]
        PrivateKey = SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkMTI=
        Address = 10.8.1.8/32

        [Peer]
        PublicKey = cGVlcmtleXBlZXJrZXlwZWVya2V5cGVlcmtleWFiY2Q=
        Endpoint = vpn.example:51820
        AllowedIPs = 0.0.0.0/0
        AllowedIPs = ::/0
        """)
    #expect(profile.supportsIPv6)
}

@Test func openVPNKeepsFilesInlineAndNativeCodeBehindApproval() throws {
    // A path after the inline block used to pass, because the block had been seen.
    #expect(throws: RouterErrorInfo.self) {
        try OpenVPNProfileParser.parse("client\ndev tun\n<ca>\nx\n</ca>\nca /etc/other.pem\n")
    }
    #expect(throws: RouterErrorInfo.self) {
        try OpenVPNProfileParser.parse("client\ndev tun\n<connection>\nremote vpn.example 1194\n</connection>\n")
    }
    let profile = try OpenVPNProfileParser.parse("client\ndev tun\nproviders legacy default\nengine dynamic\nproviders /tmp/module\n")
    #expect(profile.dangerousDirectives == ["engine dynamic", "providers /tmp/module"])
}

@Test func routesCoveringTheDefaultAreRefused() {
    #expect(throws: RouterErrorInfo.self) { try RuleSet(rules: [.init(target: .direct, kind: .cidr, value: "0.0.0.0/0")]) }
    #expect(throws: RouterErrorInfo.self) { try RuleSet(rules: [.init(target: .corporate, kind: .cidr, value: "::/1")]) }
    let pushed = OpenVPNProfileParser.pushedOptions(from: "PUSH_REPLY,route 0.0.0.0 128.0.0.0,route 128.0.0.0 128.0.0.0,route 10.0.0.0 255.0.0.0")
    #expect(pushed.routes == ["10.0.0.0/8"])
}

@Test func amneziaPassesProtocol3KeysThroughToSetConf() throws {
    // AmneziaWG 3.x adds interface knobs; awg setconf validates them, not us.
    let profile = try AmneziaWGProfileParser.parse("""
        [Interface]
        PrivateKey = SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkMTI=
        Address = 10.8.1.8/32
        H1 = 1396604382-1645267900
        HeaderProtectionKey = cGVlcmtleXBlZXJrZXlwZWVya2V5cGVlcmtleWFiY2Q=
        ContentPaddingAddition = 0-32
        RandomTrailers = on
        DisableCookies = off

        [Peer]
        PublicKey = cGVlcmtleXBlZXJrZXlwZWVya2V5cGVlcmtleWFiY2Q=
        Endpoint = vpn.example:51820
        AllowedIPs = 0.0.0.0/0
        AdvancedSecurity = on
        """)
    for line in [
        "HeaderProtectionKey = cGVlcmtleXBlZXJrZXlwZWVya2V5cGVlcmtleWFiY2Q=", "ContentPaddingAddition = 0-32",
        "RandomTrailers = on", "DisableCookies = off", "AdvancedSecurity = on",
    ] {
        #expect(profile.setConf.contains(line))
    }
}

private let testUUID = "0b5c7f1e-6a3d-4c2b-9e8f-1a2b3c4d5e6f"
/// Xray checks a REALITY key is a real x25519 key in base64url.
private let testRealityKey = "SGVsbG9Xb3JsZEhlbGxvV29ybGRIZWxsb1dvcmxkMTI"
private let testPin = "BA:88:45:17:A1:F6:ED:28:0E:8A:3D:4C:1E:2B:8A:60:3C:6D:71:9E:5F:2A:7B:44:90:C3:11:5D:26:8E:F0:12"

private func outbounds(_ server: XrayServer) throws -> [[String: Any]] {
    try JSONSerialization.jsonObject(with: Data(server.outbounds.utf8)) as? [[String: Any]] ?? []
}

private func dig(_ value: Any?, _ path: String...) -> Any? {
    path.reduce(value) { ($0 as? [String: Any])?[$1] }
}

@Test func xrayLinksBecomeOutbounds() throws {
    let reality = try XrayProfileParser.server(fromLink: "vless://\(testUUID)@vpn.example:443?type=tcp&security=reality&pbk=PUBLICKEY&sid=ab12&sni=www.microsoft.com&fp=chrome&flow=xtls-rprx-vision#%D0%A1%D0%B5%D1%80%D0%B2%D0%B5%D1%80")
    #expect(reality.name == "Сервер" && reality.host == "vpn.example" && reality.port == 443 && reality.protocolName == "vless")
    let proxy = try outbounds(reality)[0]
    #expect(proxy["tag"] as? String == "proxy")
    #expect(dig(proxy, "settings", "flow") as? String == "xtls-rprx-vision")
    #expect(dig(proxy, "streamSettings", "network") as? String == "raw")
    #expect(dig(proxy, "streamSettings", "realitySettings", "publicKey") as? String == "PUBLICKEY")

    let xhttp = try XrayProfileParser.server(fromLink: "vless://\(testUUID)@203.0.113.5:443?type=xhttp&security=tls&sni=cdn.example&path=%2Fup&mode=packet-up&extra=%7B%22xmux%22%3A%7B%22maxConcurrency%22%3A4%7D%2C%22downloadSettings%22%3A%7B%22sockopt%22%3A%7B%22interface%22%3A%22en9%22%7D%7D%7D")
    let x = try outbounds(xhttp)[0]
    #expect(dig(x, "streamSettings", "xhttpSettings", "path") as? String == "/up")
    #expect(dig(x, "streamSettings", "xhttpSettings", "extra", "xmux", "maxConcurrency") as? Int == 4)
    // extra is the server's to shape, but not to bind root's sockets.
    #expect(dig(x, "streamSettings", "xhttpSettings", "extra", "downloadSettings", "sockopt", "interface") == nil)

    let trojan = try outbounds(XrayProfileParser.server(fromLink: "trojan://p%40ss@tr.example:443?type=ws&path=%2Fws&host=tr.example#T"))[0]
    #expect(dig(trojan, "settings", "password") as? String == "p@ss")
    #expect(dig(trojan, "streamSettings", "security") as? String == "tls")

    let ss = try outbounds(XrayProfileParser.server(fromLink: "ss://" + Data("aes-256-gcm:secret".utf8).base64EncodedString() + "@ss.example:8388#SS"))[0]
    #expect(dig(ss, "settings", "method") as? String == "aes-256-gcm")

    let vmessJSON = #"{"v":"2","ps":"VM","add":"vm.example","port":"443","id":"0b5c7f1e-6a3d-4c2b-9e8f-1a2b3c4d5e6f","net":"grpc","path":"svc","type":"multi","tls":"tls","sni":"vm.example"}"#
    let vmess = try XrayProfileParser.server(fromLink: "vmess://" + Data(vmessJSON.utf8).base64EncodedString())
    #expect(vmess.name == "VM")
    #expect(dig(try outbounds(vmess)[0], "streamSettings", "grpcSettings", "serviceName") as? String == "svc")
    #expect(dig(try outbounds(vmess)[0], "streamSettings", "grpcSettings", "multiMode") as? Bool == true)
}

@Test func hysteria2LinkCarriesObfuscationPortHoppingAndItsPin() throws {
    let server = try XrayProfileParser.server(fromLink: "hysteria2://secret@hy.example:443/?sni=hy.example&obfs=salamander&obfs-password=pw&mport=20000-30000&insecure=1&pinSHA256=\(testPin)#HY")
    let proxy = try outbounds(server)[0]
    #expect(server.protocolName == "hysteria" && server.port == 443)
    #expect(dig(proxy, "settings", "version") as? Int == 2)
    #expect(dig(proxy, "streamSettings", "hysteriaSettings", "auth") as? String == "secret")
    let masks = dig(proxy, "streamSettings", "finalmask", "udp") as? [[String: Any]] ?? []
    #expect(masks.map { $0["type"] as? String } == ["salamander", "udphop"])
    #expect(dig(masks.last, "settings", "remotePorts") as? String == "20000-30000")
    // Xray no longer skips the certificate check; the pin takes its place.
    #expect(dig(proxy, "streamSettings", "tlsSettings", "pinnedPeerCertSha256") as? String == testPin)
    #expect(dig(proxy, "streamSettings", "tlsSettings", "allowInsecure") == nil)
}

@Test func xrayRejectsWhatItCannotRun() {
    for link in [
        "tuic://u:p@h.example:443",
        "vless://not-a-uuid@h.example:443",
        "vless://\(testUUID)@h.example:99999",
        "vless://\(testUUID)@h.example:443?type=kcp",
        "ss://" + Data("rc4-md5:x".utf8).base64EncodedString() + "@h.example:1",
        "hy2://pw@h.example:443/?insecure=1",
    ] {
        #expect(throws: RouterErrorInfo.self) { try XrayProfileParser.server(fromLink: link) }
    }
}

@Test func subscriptionsAreLinksBase64OrJSONAndKeepOnlyTheProxy() throws {
    let links = "vless://\(testUUID)@a.example:443?security=tls#A\ntuic://skipped@b.example:1\nhy2://pw@c.example:443#C\n"
    let plain = try XrayProfileParser.subscription(body: Data(links.utf8).base64EncodedString(), headers: [
        "profile-title": "base64:" + Data("Мой VPN".utf8).base64EncodedString(),
        "subscription-userinfo": "upload=100; download=900; total=10000; expire=1893456000",
        "profile-update-interval": "6",
    ])
    #expect(plain.servers.map(\.name) == ["A", "C"])
    #expect(plain.skipped == ["Протокол tuic не поддерживается"])
    #expect(plain.title == "Мой VPN" && plain.usedBytes == 1000 && plain.totalBytes == 10000)
    #expect(plain.updateInterval == 21_600)

    let json = """
    [{"remarks": "JSON", "inbounds": [{"protocol": "socks", "port": 1080}], "api": {"tag": "api"},
      "outbounds": [
        {"tag": "proxy", "protocol": "vless",
         "settings": {"vnext": [{"address": "j.example", "port": 443, "users": [{"id": "\(testUUID)", "encryption": "none"}]}]},
         "streamSettings": {"network": "raw", "security": "tls",
                            "tlsSettings": {"serverName": "j.example", "allowInsecure": false, "masterKeyLog": "/tmp/keys", "certificates": [{"certificateFile": "/etc/x"}]},
                            "sockopt": {"dialerProxy": "frag", "interface": "en9"}}},
        {"tag": "frag", "protocol": "freedom", "settings": {"fragment": {"packets": "tlshello", "length": "100-200"}}},
        {"tag": "direct", "protocol": "freedom"}
      ]},
     {"remarks": "Insecure", "outbounds": [{"protocol": "trojan", "settings": {"servers": [{"address": "i.example", "port": 443, "password": "x"}]},
                                            "streamSettings": {"security": "tls", "tlsSettings": {"allowInsecure": true}}}]}]
    """
    let fromJSON = try XrayProfileParser.subscription(body: json, headers: [:])
    #expect(fromJSON.servers.map(\.name) == ["JSON"])
    #expect(fromJSON.skipped.count == 1)
    let server = fromJSON.servers[0]
    #expect(server.host == "j.example" && server.port == 443)
    let hops = try outbounds(server)
    #expect(hops.map { $0["tag"] as? String } == ["proxy", "frag"])
    #expect(dig(hops[0], "streamSettings", "sockopt", "dialerProxy") as? String == "frag")
    #expect(dig(hops[0], "streamSettings", "sockopt", "interface") == nil)
    #expect(dig(hops[0], "streamSettings", "tlsSettings", "masterKeyLog") == nil)
    #expect(dig(hops[0], "streamSettings", "tlsSettings", "certificates") == nil)
    #expect(dig(hops[0], "streamSettings", "tlsSettings", "allowInsecure") == nil)
    #expect(!server.outbounds.contains("inbounds") && !server.outbounds.contains("\"api\""))
}

@Test func vpnServerNameStaysDirectUnderItsPushedCorporateDomain() throws {
    let rules = try RuleSet(
        rules: [.init(target: .corporate, kind: .domain, value: "corp.example")],
        endpoints: ["vpn.corp.example"]
    )
    #expect(rules.classify(domain: "VPN.corp.example.") == .direct)
    #expect(rules.classify(domain: "mail.corp.example") == .corporate)
    #expect(rules.classify(domain: "a.vpn.corp.example") == .corporate)
    #expect(rules.domainSuffixes.contains("vpn.corp.example"))
}

@Test func subscriptionHeadersCarryTheProvidersWordsButOnlyWebLinks() throws {
    let fetched = try XrayProfileParser.subscription(body: "vless://\(testUUID)@a.example:443?security=tls#A", headers: [
        "announce": "base64:" + Data("Скидка 20% до конца месяца".utf8).base64EncodedString(),
        "support-url": " https://t.me/support ",
        "profile-web-page-url": "javascript:alert(1)",
    ])
    #expect(fetched.announce == "Скидка 20% до конца месяца")
    #expect(fetched.supportURL?.absoluteString == "https://t.me/support")
    #expect(fetched.webPageURL == nil)
    #expect(try XrayProfileParser.subscription(body: "vless://\(testUUID)@a.example:443#A", headers: ["announce": " "]).announce == nil)
}

@Test func subscriptionUserAgentIsOneHeaderLine() throws {
    let happ = "Happ/4.8.3/macos catalyst/2604271932679"
    #expect(try XrayProfileParser.userAgent(" \(happ) ") == happ)
    #expect(try XrayProfileParser.userAgent("") == nil)
    #expect(throws: RouterErrorInfo.self) { try XrayProfileParser.userAgent("Happ\r\nX-Evil: 1") }
}

@Test func xrayConfigurationHasOnlyOurDoorsAndXrayAcceptsIt() throws {
    let servers = try [
        "vless://\(testUUID)@a.example:443?type=tcp&security=reality&pbk=\(testRealityKey)&sid=ab12&sni=www.microsoft.com&flow=xtls-rprx-vision#R",
        "vless://\(testUUID)@a.example:443?type=xhttp&security=tls&sni=a.example&path=%2Fx#X",
        "trojan://pw@a.example:443?type=grpc&serviceName=svc#T",
        "ss://" + Data("2022-blake3-aes-128-gcm:MTIzNDU2Nzg5MDEyMzQ1Ng==".utf8).base64EncodedString() + "@a.example:8388#S",
        "hysteria2://pw@a.example:443/?sni=a.example&obfs=salamander&obfs-password=pw&mport=20000-30000#H",
    ].map(XrayProfileParser.server(fromLink:))
    let probe = XrayProbe(port: 23456, user: "u", password: "p")
    let text = try XrayProfileParser.configuration(for: servers[0], interface: "utun120", physicalInterface: "en0", probe: probe)
    let config = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] ?? [:]
    let inbounds = config["inbounds"] as? [[String: Any]] ?? []
    #expect(inbounds.map { $0["protocol"] as? String } == ["tun", "socks"])
    #expect(dig(inbounds[0], "settings", "name") as? String == "utun120")
    #expect(dig(inbounds[0], "settings", "autoOutboundsInterface") as? String == "en0")
    #expect(inbounds[1]["listen"] as? String == "127.0.0.1")
    #expect(dig(inbounds[1], "settings", "auth") as? String == "password")
    #expect(config["api"] == nil && config["routing"] == nil)

    // Xray's own parser has the last word, when the binary is there to ask.
    let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let xray = root.appendingPathComponent("Vendor/bin/arm64/xray").path
    guard FileManager.default.isExecutableFile(atPath: xray) else { return }
    for server in servers {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("xray-\(UUID().uuidString).json")
        try XrayProfileParser.configuration(for: server, interface: "utun120", physicalInterface: "en0", probe: probe)
            .write(to: url, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: url) }
        let result = try CommandRunner.live.run(xray, ["run", "-test", "-c", url.path])
        #expect(result.status == 0, "\(server.name): \(result.stdout) \(result.stderr)")
    }
}

@Test func logRedactorHidesIdentitiesAndKeepsWhatExplainsAFailure() {
    let redactor = LogRedactor()
    redactor.register(host: "vpn.example.org")
    let line = redactor.redact(
        "route 198.51.100.7 255.255.255.0 → vpn.example.org via utun5/en0, CN=Acme CA, emailAddress=admin@acme.example, ifconfig 192.168.250.30"
    )
    #expect(!line.contains("198.51.100.7"))
    #expect(!line.contains("vpn.example.org"))
    #expect(!line.contains("admin@acme.example"))
    #expect(!line.contains("Acme CA"))
    // Without these a log says nothing about where a handshake went.
    #expect(line.contains("utun5") && line.contains("en0"))
    #expect(line.contains("255.255.255.0"), "маска сети — не адрес сервера")
    #expect(line.contains("192.168.250.30"), "частные адреса остаются: они никого не выдают")
    // The same address keeps the same alias, so a route and a handshake still tie together.
    #expect(line.contains("адрес#1") && redactor.redact("handshake to 198.51.100.7").contains("адрес#1"))
    #expect(redactor.redact("запуск /var/run/com.vpnrouter/openvpn.conf").contains("com.vpnrouter/openvpn.conf"))
}

@Test func commandOutputPastThePipeBufferDoesNotHang() throws {
    let result = try CommandRunner.live.run("/bin/dd", ["if=/dev/zero", "bs=1024", "count=200"])
    #expect(result.status == 0)
    #expect(result.stdout.utf8.count == 204_800)
}
