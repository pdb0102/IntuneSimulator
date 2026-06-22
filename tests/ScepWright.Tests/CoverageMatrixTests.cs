using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using ScepWright.Core;
using ScepWright.Core.Storage;
using ScepWright.Core.Testing;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Tests.Fakes;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public sealed class CoverageMatrixTests {
    // The documented coverage matrix must justify what the suites prove — and must not
    // drift. Every check the full/lifecycle/probe suites actually emit has to appear in the matrix, so a
    // newly-added check can't ship silently undocumented.
    [Fact]
    public async Task Coverage_matrix_documents_every_check_the_suites_emit() {
        ScepServerApp server;
        ScepClient client;
        CertStore store;
        UseRecordLog log;
        HashSet<string> emitted;
        HashSet<string> documented;

        server = await ScepServerApp.StartAsync();
        try {
            client = BuildClientForWithStore(server, out store, out log);
            emitted = new HashSet<string>();
            CollectNames(emitted, new ComplianceEngine().RunFull(client, client.GetCaCert().Value, client.GetCaCaps().Value));
            CollectNames(emitted, new TestEngine().RunLifecycle(client, store, log));
            CollectNames(emitted, new TestEngine().RunProbe(client));

            documented = CoverageMatrixDoc.Entries.Select(e => e.Check).ToHashSet();
            foreach (string name in emitted) {
                Assert.True(documented.Contains(name), $"check '{name}' is emitted by a suite but missing from the coverage matrix");
            }
        } finally {
            await server.DisposeAsync();
        }
    }

    // The rendered matrix is real markdown: a table per suite, every entry present.
    [Fact]
    public void Render_emits_a_markdown_row_per_entry() {
        string md;

        md = CoverageMatrixDoc.Render();
        Assert.Contains("# SCEP conformance coverage matrix", md);
        foreach (CoverageMatrixDoc.Entry e in CoverageMatrixDoc.Entries) {
            Assert.Contains(e.Check, md);
        }
    }

    // The committed docs/coverage-matrix.md is the rendered output; keep them in lockstep so the doc
    // can never go stale. Regenerate with the same Render() if this fails.
    [Fact]
    public void Committed_doc_matches_rendered_output() {
        string repo_root;
        string doc_path;
        string committed;

        repo_root = FindRepoRoot();
        doc_path = System.IO.Path.Combine(repo_root, "docs", "coverage-matrix.md");
        Assert.True(System.IO.File.Exists(doc_path), $"missing {doc_path}");
        committed = System.IO.File.ReadAllText(doc_path).Replace("\r\n", "\n");
        Assert.Equal(CoverageMatrixDoc.Render().Replace("\r\n", "\n"), committed);
    }

    private static string FindRepoRoot() {
        System.IO.DirectoryInfo? dir;

        dir = new System.IO.DirectoryInfo(System.AppContext.BaseDirectory);
        while (dir != null) {
            if (System.IO.File.Exists(System.IO.Path.Combine(dir.FullName, "SCEPwright.sln"))) { return dir.FullName; }
            dir = dir.Parent;
        }
        throw new System.IO.DirectoryNotFoundException("could not locate repo root (SCEPwright.sln)");
    }

    private static void CollectNames(HashSet<string> into, TestReport report) {
        foreach (CheckResult r in report.Results) { into.Add(r.Name); }
    }

    private static ScepClient BuildClientForWithStore(ScepServerApp server, out CertStore store, out UseRecordLog log) {
        BouncyCastleScepCrypto crypto;
        ScepClient client;
        string root;

        root = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "scepwright-cov-" + System.Guid.NewGuid().ToString("N"));
        store = new CertStore(root);
        log = new UseRecordLog(root);
        crypto = new BouncyCastleScepCrypto();
        ScepClient.Create(new ServerConfig { Id = "fake", Url = server.ScepUrl, PreferPost = true }, crypto, handler: null, out client, out _);
        return client;
    }
}
