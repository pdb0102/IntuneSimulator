using System.IO;
using System.Threading.Tasks;
using ScepWright.Client;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public sealed class CliTestCommandTests {
    [Fact]
    public async Task TestProbe_PrintsSummary_AndWritesJunit() {
        await using ScepServerApp server = await ScepServerApp.StartAsync();
        string root;
        StringWriter output;
        int code;
        StringWriter add_out;

        root = Path.Combine(Path.GetTempPath(), "sceptest-" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        add_out = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "testhost" }, root, add_out);

        output = new StringWriter();
        code = CommandRouter.Run(new[] { "test", "probe", "testhost", "--report-format", "junit" }, root, output);

        Assert.Contains("SCEP test run", output.ToString());
        Assert.True(Directory.Exists(Path.Combine(root, "runs")));
        Assert.NotEmpty(Directory.GetFiles(Path.Combine(root, "runs"), "*.junit.xml"));
        Assert.InRange(code, 0, 1);
    }

    // `test`/`run` accept --challenge and plumb it into the suite so CI can exercise a
    // challenge-protected CA. Without the challenge the lifecycle enroll fails (exit 1); with it, exit 0.
    [Fact]
    public async Task TestLifecycle_AgainstChallengeCa_NeedsChallengeFlag() {
        ScepCa ca;
        string root;
        StringWriter add_out;
        StringWriter without_out;
        StringWriter with_out;
        int without_code;
        int with_code;

        ca = ScepCa.Create();
        ca.ExpectedChallenge = "ci-challenge";
        await using ScepServerApp server = await ScepServerApp.StartAsync(ca);

        root = Path.Combine(Path.GetTempPath(), "sceptest-" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        add_out = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "chal" }, root, add_out);

        without_out = new StringWriter();
        without_code = CommandRouter.Run(new[] { "lifecycle", "chal" }, root, without_out);
        Assert.Equal(1, without_code);

        with_out = new StringWriter();
        with_code = CommandRouter.Run(new[] { "lifecycle", "chal", "--challenge", "ci-challenge" }, root, with_out);
        Assert.Equal(0, with_code);
    }

    // --dry-run runs only read-only checks and issues nothing, so even against a
    // challenge-protected CA with NO challenge supplied it exits 0 (where a real lifecycle would fail).
    [Fact]
    public async Task TestDryRun_AgainstChallengeCa_IssuesNothing_Exit0() {
        ScepCa ca;
        string root;
        StringWriter add_out;
        StringWriter normal_out;
        StringWriter dry_out;
        int normal_code;
        int dry_code;

        ca = ScepCa.Create();
        ca.ExpectedChallenge = "x";
        await using ScepServerApp server = await ScepServerApp.StartAsync(ca);

        root = Path.Combine(Path.GetTempPath(), "sceptest-" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);
        add_out = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", server.ScepUrl.ToString(), "--name", "dry" }, root, add_out);

        normal_out = new StringWriter();
        normal_code = CommandRouter.Run(new[] { "lifecycle", "dry" }, root, normal_out);
        Assert.Equal(1, normal_code);

        dry_out = new StringWriter();
        dry_code = CommandRouter.Run(new[] { "lifecycle", "dry", "--dry-run" }, root, dry_out);
        Assert.Equal(0, dry_code);
        Assert.Contains("dry-run", dry_out.ToString());
    }

    // `test diagnose` must NOT claim diagnose issues real certs (it's read-only); it should point the
    // user at running diagnose directly, and never print the blast-radius banner.
    [Fact]
    public void Test_diagnose_is_routed_not_mislabeled() {
        string root;
        StringWriter output;
        int code;
        string text;

        root = Path.Combine(Path.GetTempPath(), "sceptest-" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        output = new StringWriter();
        code = CommandRouter.Run(new[] { "test", "diagnose", "somehost" }, root, output);
        text = output.ToString();

        Assert.Equal(2, code);
        Assert.Contains("read-only", text);
        Assert.Contains("diagnose somehost", text);
        Assert.DoesNotContain("REAL certificates", text);
    }

    [Fact]
    public void Test_UnknownVerb_Usage() {
        string root;
        StringWriter output;
        int code;
        StringWriter add_out;

        root = Path.Combine(Path.GetTempPath(), "sceptest-" + System.Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(root);

        add_out = new StringWriter();
        CommandRouter.Run(new[] { "servers", "add", "http://host/scep", "--name", "testhost" }, root, add_out);

        output = new StringWriter();
        code = CommandRouter.Run(new[] { "test", "bogus", "testhost" }, root, output);
        Assert.Equal(2, code);
    }
}
