using System.Net;
using System.Net.NetworkInformation;
using FNPPAnalyzer.Config;
using FNPPAnalyzer.Engine;
using FNPPAnalyzer.Rules.Network;

namespace FNPPAnalyzer.Tests;

public class NetworkRuleTests
{
    // TcpConnectionInformation is abstract with abstract properties — fake it directly.
    private sealed class FakeTcpConnection : TcpConnectionInformation
    {
        private readonly IPEndPoint _local, _remote;
        private readonly TcpState _state;

        public FakeTcpConnection(string remoteIp, int remotePort, TcpState state = TcpState.Established)
        {
            _local  = new IPEndPoint(IPAddress.Parse("192.168.1.10"), 50000);
            _remote = new IPEndPoint(IPAddress.Parse(remoteIp), remotePort);
            _state  = state;
        }

        public override IPEndPoint LocalEndPoint => _local;
        public override IPEndPoint RemoteEndPoint => _remote;
        public override TcpState State => _state;
    }

    private static ScanContext Ctx(
        TcpConnectionInformation[]? conns = null,
        List<TcpConnectionWithPid>? pidConns = null,
        Dictionary<int, string>? paths = null) => new()
    {
        TcpConnections = conns ?? [],
        TcpConnectionsWithPid = pidConns ?? [],
        ProcessPaths = paths ?? new()
    };

    // ── NET-001: Suspicious ports ─────────────────────────────────────────────

    [Fact]
    public void Net001_MetasploitPort_IsFlagged_WithStableDedupeKey()
    {
        var rule = new SuspiciousNetworkActivityRule(AppConfig.CreateDefault());

        var events = rule.Evaluate(Ctx(conns: [new FakeTcpConnection("203.0.113.5", 4444)]));

        var evt = Assert.Single(events, e => e.RuleId == "NET-001");
        Assert.Equal("203.0.113.5:4444", evt.DedupeKey);
    }

    [Fact]
    public void Net001_CommonDevPorts_AreNotInTheDefaultList()
    {
        // 8888 (Jupyter) and 5000 (Flask/Docker/AirPlay) fired constantly on developer
        // machines — they were removed from the default port list.
        var rule = new SuspiciousNetworkActivityRule(AppConfig.CreateDefault());

        var events = rule.Evaluate(Ctx(conns:
        [
            new FakeTcpConnection("203.0.113.5", 8888),
            new FakeTcpConnection("203.0.113.5", 5000)
        ]));

        Assert.DoesNotContain(events, e => e.RuleId == "NET-001");
    }

    [Fact]
    public void Net001_PortListIsConfigurable()
    {
        var config = AppConfig.CreateDefault();
        config.SuspiciousPorts.Add(8888);
        var rule = new SuspiciousNetworkActivityRule(config);

        var events = rule.Evaluate(Ctx(conns: [new FakeTcpConnection("203.0.113.5", 8888)]));

        Assert.Contains(events, e => e.RuleId == "NET-001");
    }

    // ── NET-002: Outbound port scan ───────────────────────────────────────────

    [Fact]
    public void Net002_ManyDistinctPortsOnOneRemoteIp_IsFlagged_KeyedByTargetIp()
    {
        var rule = new SuspiciousNetworkActivityRule(AppConfig.CreateDefault());

        var conns = new TcpConnectionInformation[25];
        for (int i = 0; i < conns.Length; i++)
            conns[i] = new FakeTcpConnection("203.0.113.9", 1000 + i);

        var events = rule.Evaluate(Ctx(conns: conns));

        var evt = Assert.Single(events, e => e.RuleId == "NET-002");
        // Description embeds the volatile port count; dedup must key on the target IP
        Assert.Equal("203.0.113.9", evt.DedupeKey);
    }

    // ── NET-003: Connection burst ─────────────────────────────────────────────

    [Fact]
    public void Net003_AboveThreshold_IsFlagged_WithConstantDedupeKey()
    {
        var config = AppConfig.CreateDefault();
        config.Rules["NET-003"] = new RuleConfig { Enabled = true, Threshold = 10 };
        var rule = new SuspiciousNetworkActivityRule(config);

        var conns = new TcpConnectionInformation[15];
        for (int i = 0; i < conns.Length; i++)
            conns[i] = new FakeTcpConnection($"198.51.100.{i + 1}", 443);

        var events = rule.Evaluate(Ctx(conns: conns));

        var evt = Assert.Single(events, e => e.RuleId == "NET-003");
        Assert.Equal("connection-burst", evt.DedupeKey);
    }

    // ── NET-004: Tor / untrusted-process connections ──────────────────────────

    [Fact]
    public void Net004_TorPort_FromTrustedInstallPath_IsNotFlagged()
    {
        // 9001 is also SonarQube/HDFS/Tomcat — a process running from a trusted
        // install path connecting there must not raise a HIGH Tor alert.
        var config = AppConfig.CreateDefault();
        string trustedExe = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), @"Java\bin\java.exe");
        var rule = new SuspiciousNetworkActivityRule(config);

        var events = rule.Evaluate(Ctx(
            pidConns: [new TcpConnectionWithPid(
                IPAddress.Parse("192.168.1.10"), 50000,
                IPAddress.Parse("203.0.113.20"), 9001,
                NetworkHelper.MIB_TCP_STATE_ESTAB, OwningPid: 42)],
            paths: new() { [42] = trustedExe }));

        Assert.DoesNotContain(events, e => e.RuleId == "NET-004");
    }

    [Fact]
    public void Net004_TorPort_FromUserWritablePath_IsFlagged()
    {
        var rule = new SuspiciousNetworkActivityRule(AppConfig.CreateDefault());

        var events = rule.Evaluate(Ctx(
            pidConns: [new TcpConnectionWithPid(
                IPAddress.Parse("192.168.1.10"), 50000,
                IPAddress.Parse("203.0.113.20"), 9001,
                NetworkHelper.MIB_TCP_STATE_ESTAB, OwningPid: 42)],
            paths: new() { [42] = @"C:\Users\bob\AppData\Roaming\tor.exe" }));

        Assert.Contains(events, e => e.RuleId == "NET-004");
    }

    [Fact]
    public void Net004_UntrustedProcessWithExternalConnection_IsFlagged()
    {
        var rule = new SuspiciousNetworkActivityRule(AppConfig.CreateDefault());

        var events = rule.Evaluate(Ctx(
            pidConns: [new TcpConnectionWithPid(
                IPAddress.Parse("192.168.1.10"), 50000,
                IPAddress.Parse("203.0.113.30"), 443,
                NetworkHelper.MIB_TCP_STATE_ESTAB, OwningPid: 7)],
            paths: new() { [7] = @"C:\Users\bob\Downloads\payload.exe" }));

        var evt = Assert.Single(events, e => e.RuleId == "NET-004");
        Assert.Equal(@"C:\Users\bob\Downloads\payload.exe", evt.ExecutablePath);
    }

    [Fact]
    public void Net004_PrivateAndLoopbackDestinations_AreIgnored()
    {
        var rule = new SuspiciousNetworkActivityRule(AppConfig.CreateDefault());

        var events = rule.Evaluate(Ctx(
            pidConns: [new TcpConnectionWithPid(
                IPAddress.Parse("192.168.1.10"), 50000,
                IPAddress.Parse("192.168.1.20"), 9001,
                NetworkHelper.MIB_TCP_STATE_ESTAB, OwningPid: 7)],
            paths: new() { [7] = @"C:\Users\bob\Downloads\payload.exe" }));

        Assert.DoesNotContain(events, e => e.RuleId == "NET-004");
    }
}
