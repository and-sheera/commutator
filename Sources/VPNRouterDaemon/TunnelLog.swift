import Foundation
import VPNRouterCore

/// Everything the tunnels and the router say: on disk for `sudo cat`, and the
/// newest lines in memory for the app's live view. Never credentials, and never
/// a name the user's machine looked up.
///
/// Server names and addresses are what makes a handshake that never completes
/// explainable, so they stay — as stable aliases, because this log is written to
/// be sent to someone else. `VPNROUTER_LOG_RAW=1` keeps them verbatim, for an
/// ad-hoc dev build only.
///
/// ponytail: reopens the file per line. openvpn at verb 3 writes tens of lines
/// per connection, so a kept-open handle would only add reopen-after-rotate
/// bookkeeping for no measurable gain.
final class TunnelLog: @unchecked Sendable {
    static let shared = TunnelLog()

    let path: String
    private let lock = NSLock()
    private let limit: Int
    /// A verbose engine fills a thousand lines in minutes, and what led up to a
    /// failure is exactly what has to still be there when it is read.
    private let kept = 10_000
    private let redactor = LogRedactor()
    private let redacts = ProcessInfo.processInfo.environment["VPNROUTER_LOG_RAW"] != "1"
    private var recent: [String] = []
    private var sequence = 0
    private let formatter: ISO8601DateFormatter = {
        // Local time: the log is read next to the menu bar clock, not in UTC.
        let formatter = ISO8601DateFormatter()
        formatter.timeZone = .current
        formatter.formatOptions = [.withFullDate, .withTime, .withColonSeparatorInTime, .withSpaceBetweenDateAndTime]
        return formatter
    }()

    init(path: String = "/var/log/vpn-router.log", limit: Int = 8_000_000) {
        self.path = path
        self.limit = limit
    }

    func write(_ source: String, _ line: String) {
        let text = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        // The management channel takes credentials as "username"/"password"
        // commands; nothing echoes them back, but the log must not be the first
        // place where that stops being true.
        let lowercased = text.lowercased()
        var safe = lowercased.hasPrefix("password ") || lowercased.hasPrefix("username ") ? "<скрыто>" : text
        if redacts { safe = redactor.redact(safe) }
        let entry = "\(formatter.string(from: Date())) [\(source)] \(safe)"
        lock.lock()
        defer { lock.unlock() }
        sequence += 1
        recent.append(entry)
        if recent.count > kept { recent.removeFirst(recent.count - kept) }
        trimIfNeeded()
        guard let handle = FileHandle(forWritingAtPath: path) ?? create() else { return }
        defer { try? handle.close() }
        _ = try? handle.seekToEnd()
        try? handle.write(contentsOf: Data((entry + "\n").utf8))
    }

    /// A server the daemon works with: it gets an alias in the log instead of its
    /// name. Registered rather than guessed — see `LogRedactor`.
    func register(host: String) { redactor.register(host: host) }

    /// The lines written after `cursor`. A cursor from before a daemon restart
    /// is ahead of `sequence`, and gets everything still kept.
    func lines(after cursor: Int) -> LogChunk {
        lock.lock()
        defer { lock.unlock() }
        let fresh = cursor > sequence ? recent.count : min(sequence - cursor, recent.count)
        return .init(lines: Array(recent.suffix(fresh)), next: sequence)
    }

    private func create() -> FileHandle? {
        guard FileManager.default.createFile(atPath: path, contents: nil) else { return nil }
        chmod(path, S_IRUSR | S_IWUSR)
        return FileHandle(forWritingAtPath: path)
    }

    // Keeps the newer half: a connection attempt is only worth reading together
    // with what led up to it, so dropping the whole file would defeat the point.
    private func trimIfNeeded() {
        guard let size = try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int, size > limit,
              let data = FileManager.default.contents(atPath: path)
        else { return }
        let tail = data.suffix(limit / 2)
        let start = tail.firstIndex(of: UInt8(ascii: "\n")).map { tail.index(after: $0) } ?? tail.startIndex
        try? Data(tail[start...]).write(to: URL(fileURLWithPath: path), options: .atomic)
        chmod(path, S_IRUSR | S_IWUSR)
    }
}
