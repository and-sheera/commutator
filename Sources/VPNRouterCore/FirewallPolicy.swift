import Foundation

/// One route's addresses and where they may leave.
public struct FirewallLane: Equatable, Sendable {
    /// Its tunnel, while that is up.
    public var interface: String?
    /// Out through the network: a route without a VPN, or one whose VPN is
    /// down and that is not to block meanwhile.
    public var direct: Bool
    public var addresses: [String]

    public init(interface: String? = nil, direct: Bool = false, addresses: [String] = []) {
        self.interface = interface
        self.direct = direct
        self.addresses = addresses
    }
}

public struct FirewallPolicyInput: Sendable {
    public var physicalInterface: String
    public var control: [String]
    public var lan: [String]
    /// In priority order: an address in two lanes may leave only as the first says.
    public var lanes: [FirewallLane]
    /// Every tunnel that is up. Whatever reaches one passes: routes send it
    /// there only for its own lane, for the rest when it carries the rest, or
    /// for a socket bound to it on purpose, as the app's check is.
    public var tunnels: [String]
    /// What no lane claims leaves on the physical interface instead of being
    /// dropped.
    public var directByDefault: Bool

    public init(
        physicalInterface: String,
        control: [String] = [],
        lan: [String] = [],
        lanes: [FirewallLane] = [],
        tunnels: [String] = [],
        directByDefault: Bool = false
    ) {
        self.physicalInterface = physicalInterface
        self.control = control
        self.lan = lan
        self.lanes = lanes
        self.tunnels = tunnels
        self.directByDefault = directByDefault
    }
}

public enum FirewallPolicyRenderer {
    public static func render(_ input: FirewallPolicyInput) throws -> String {
        guard let physical = safeInterface(input.physicalInterface) else {
            throw RouterErrorInfo(.firewallFailure, "Некорректное имя физического интерфейса")
        }
        let control = try validatedAddresses(input.control)
        let lan = try validatedAddresses(input.lan)
        var lines = [
            table("control4", control.filter { !$0.contains(":") }), table("control6", control.filter { $0.contains(":") }),
            table("lan", lan),
        ]
        var rules = [
            "pass quick on lo0 all no state",
            // Link-local and multicast never leave the link, whatever interface
            // carries them: the iPhone's USB link for Xcode, AWDL, Thunderbolt Bridge.
            "pass out quick to { \(linkLocal.joined(separator: ", ")) } no state",
            "pass out quick on \(physical) proto udp from any port 68 to any port 67 no state",
            "pass out quick on \(physical) to { <control4>, <control6>, <lan> } no state",
        ]
        for (index, lane) in input.lanes.enumerated() {
            let addresses = try validatedAddresses(lane.addresses)
            let v4 = "lane\(index)v4", v6 = "lane\(index)v6"
            lines += [table(v4, addresses.filter { !$0.contains(":") }), table(v6, addresses.filter { $0.contains(":") })]
            let target = "{ <\(v4)>, <\(v6)> }"
            if let interface = try lane.interface.map(validatedInterface) { rules.append("pass out quick on \(interface) to \(target) no state") }
            if lane.direct { rules.append("pass out quick on \(physical) to \(target) no state") }
            rules.append("block drop out quick to \(target)")
        }
        // Unique local IPv6 is not routed on the internet; macOS runs the
        // CoreDevice tunnel to an iPhone (Xcode) over it. After the lanes, so a
        // VPN that pushes such a network keeps its kill switch.
        rules.append("pass out quick to fc00::/7 no state")
        for tunnel in try Set(input.tunnels.map(validatedInterface)).sorted() {
            rules.append("pass out quick on \(tunnel) all no state")
        }
        if input.directByDefault { rules.append("pass out quick on \(physical) all no state") }
        rules.append("block drop out quick all")
        return (lines + rules).joined(separator: "\n") + "\n"
    }

    private static let linkLocal = ["169.254.0.0/16", "224.0.0.0/4", "fe80::/10", "ff00::/8"]

    private static func table(_ name: String, _ values: [String]) -> String {
        values.isEmpty ? "table <\(name)> persist" : "table <\(name)> persist { \(values.joined(separator: ", ")) }"
    }

    private static func validatedInterface(_ name: String) throws -> String {
        guard let value = safeInterface(name) else { throw RouterErrorInfo(.firewallFailure, "Некорректное имя VPN-интерфейса") }
        return value
    }

    private static func validatedAddresses(_ values: [String]) throws -> [String] {
        try Set(values.map { value in
            if let address = IPAddress(value) { return address.description }
            if let network = CIDR(value) { return network.description }
            throw RouterErrorInfo(.firewallFailure, "Некорректный адрес в политике: \(value)")
        }).sorted()
    }

    private static func safeInterface(_ name: String) -> String? {
        name.range(of: "^[a-zA-Z][a-zA-Z0-9]{0,15}$", options: .regularExpression) == nil ? nil : name
    }
}
