using System;
using System.Text;

namespace ScepWright.Server.Host;

/// <summary>
/// Resolves the CA key passphrase used to encrypt-on-persist and decrypt-on-load, without forcing it
/// onto the command line (where it lands in shell history and the process table). Precedence: explicit
/// <c>--key-pass</c> flag, then the <c>SCEPWRIGHT_CA_KEY_PASS</c> environment variable, then — only for
/// a real interactive scepca session — a hidden console prompt.
/// </summary>
/// <remarks>
/// Standalone reimplementation of the client's <c>PassphrasePrompt</c> (this project does not reference
/// the client). Console reads are gated behind <see cref="Interactive"/>, which only the scepca binary
/// entrypoint sets true; tests leave it off so they never touch the console.
/// </remarks>
public static class CaKeyPassphrase {
    private const string EnvVarName = "SCEPWRIGHT_CA_KEY_PASS";

    /// <summary>Gets or sets whether interactive console prompts are permitted. Off by default; the scepca entrypoint opts in, and tests leave it off.</summary>
    public static bool Interactive { get; set; }

    /// <summary>Resolves the CA key passphrase from the flag, environment variable, or a hidden prompt, in that order.</summary>
    /// <param name="flag">The passphrase supplied on the command line, or <c>null</c>.</param>
    /// <returns>The resolved passphrase, or <c>null</c> if none was available.</returns>
    public static string? Resolve(string? flag) {
        string? env;

        if (!string.IsNullOrEmpty(flag)) {
            return flag;
        }

        env = Environment.GetEnvironmentVariable(EnvVarName);
        if (!string.IsNullOrEmpty(env)) {
            return env;
        }

        if (!Interactive || Console.IsInputRedirected) {
            return null;
        }

        return ReadHidden("CA key passphrase");
    }

    private static string? ReadHidden(string label) {
        StringBuilder builder;
        ConsoleKeyInfo info;

        builder = new StringBuilder();
        Console.Error.Write($"{label}: ");

        info = Console.ReadKey(intercept: true);
        while (info.Key != ConsoleKey.Enter) {
            if (info.Key == ConsoleKey.Backspace) {
                if (builder.Length > 0) { builder.Length--; }
            } else if (!char.IsControl(info.KeyChar)) {
                builder.Append(info.KeyChar);
            }
            info = Console.ReadKey(intercept: true);
        }
        Console.Error.WriteLine();

        return builder.Length == 0 ? null : builder.ToString();
    }
}
