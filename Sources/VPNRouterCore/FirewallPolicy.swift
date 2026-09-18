import Foundation

public struct FirewallPolicyInput: Sendable {
    public var physicalInterface: String
    public var openVPNInterface: String?
    public var amneziaWGInterface: String?
    public var corporate: [String]
    public var direct: [String]
    public var control: [String]
    public var lan: [String]
    /// AmneziaWG is not in use: what no rule claims leaves on the physical
    /// interface instead of being dropped.
    public var directByDefault: Bool

    public init(
        physicalInterface: String,
        openVPNInterface: String? = nil,
        amneziaWGInterface: String? = nil,
        corporate: [String] = [],
        direct: [String] = [],
        control: [String] = [],
        lan: [String] = [],
        directByDefault: Bool = false
    ) {
        self.directByDefault = directByDefault
        self.physicalInterface = physicalInterface
        self.openVPNInterface = openVPNInterface
        self.amneziaWGInterface = amneziaWGInterface
        self.corporate = corporate
        self.direct = direct
        self.control = control
        self.lan = lan
    }
}

public enum FirewallPolicyRenderer {
    public static func render(_ input: FirewallPolicyInput) throws -> String {
        guard let physical = safeInterface(input.physicalInterface) else {
            throw RouterErrorInfo(.firewallFailure, "Некорректное имя физического интерфейса")
        }
        let openVPN = try input.openVPNInterface.map(validatedInterface)
        let awg = try input.amneziaWGInterface.map(validatedInterface)
        let corporate = try validatedAddresses(input.corporate)
        let direct = try validatedAddresses(input.direct)
        let control = try validatedAddresses(input.control)
        let lan = try validatedAddresses(input.lan)
        let corporate4 = corporate.filter { !$0.contains(":") }
        let corporate6 = corporate.filter { $0.contains(":") }
        let direct4 = direct.filter { !$0.contains(":") }
        let direct6 = direct.filter { $0.contains(":") }
        let control4 = control.filter { !$0.contains(":") }
        let control6 = control.filter { $0.contains(":") }
        var lines = [
            table("corp4", corporate4), table("corp6", corporate6),
            table("direct4", direct4), table("direct6", direct6),
            table("control4", control4), table("control6", control6),
            table("lan", lan),
            "pass quick on lo0 all no state",
            "pass out quick on \(physical) proto udp from any port 68 to any port 67 no state",
            "pass out quick on \(physical) to { <control4>, <control6>, <lan> } no state",
        ]
        if let openVPN { lines.append("pass out quick on \(openVPN) to { <corp4>, <corp6> } no state") }
        lines += [
            "block drop out quick to { <corp4>, <corp6> }",
            "pass out quick on \(physical) to { <direct4>, <direct6> } no state",
            "block drop out quick to { <direct4>, <direct6> }",
        ]
        if let awg { lines.append("pass out quick on \(awg) all no state") }
        if input.directByDefault { lines.append("pass out quick on \(physical) all no state") }
        lines.append("block drop out quick all")
        return lines.joined(separator: "\n") + "\n"
    }

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
