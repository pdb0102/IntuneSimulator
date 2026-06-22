using System.IO;
using System.Text.Json;
using ScepWright.Core;
using ScepWright.Crypto;

namespace ScepWright.Core.Storage;

/// <summary>Append-only JSONL audit log of SCEP operations, per server, under the data root.</summary>
public sealed class UseRecordLog {
    private readonly string _root;

    /// <summary>Creates the log rooted at the given data directory.</summary>
    public UseRecordLog(string root) {
        _root = root;
    }

    /// <summary>Appends a use record to the server's history.jsonl.</summary>
    public void Append(string server_id, UseRecord record) {
        string server_dir;
        string history_file;
        string line;

        server_dir = Path.Combine(_root, "servers", server_id);
        Directory.CreateDirectory(server_dir);
        history_file = Path.Combine(server_dir, "history.jsonl");
        line = JsonSerializer.Serialize(record) + "\n";
        File.AppendAllText(history_file, line);
    }

    /// <summary>Builds and appends a use record from an enrollment/renewal outcome.</summary>
    public void Append(string server_id, EnrollOutcome outcome) {
        UseRecord record;
        string? cert_id;

        cert_id = outcome.Certificate?.Thumbprint;
        record = new UseRecord {
            Operation = "Enroll",
            PkiStatus = outcome.PkiStatus.ToString(),
            TimingMs = (long)outcome.Elapsed.TotalMilliseconds,
            CertId = cert_id,
            FailInfo = outcome.FailInfo == ScepWright.Crypto.FailInfo.None
                ? null
                : outcome.FailInfo.ToString(),
            TransactionId = outcome.TransactionId,
        };
        Append(server_id, record);
    }
}
