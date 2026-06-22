using System;
using System.Text;

namespace ScepWright.Client;

/// <summary>
/// Resolves a key passphrase without forcing it onto the command line (where it would land in shell
/// history and the process table). Precedence: explicit <c>--key-pass</c> flag, then the
/// <c>SCEPWRIGHT_KEY_PASS</c> environment variable, then — only for real interactive CLI sessions —
/// a hidden prompt, or a single stdin line when input is piped.
/// </summary>
/// <remarks>
/// Console reads are gated behind <see cref="Interactive"/> (set by the binary entrypoints, never in
/// tests) so the shared <see cref="CommandRouter"/> never blocks on stdin when driven programmatically.
/// </remarks>
public static class PassphrasePrompt {
    private const string EnvVarName = "SCEPWRIGHT_KEY_PASS";

    /// <summary>Gets or sets whether interactive console prompts are permitted. Off by default; the scepclient/scepwright entrypoints opt in, and tests leave it off.</summary>
    public static bool Interactive { get; set; }

    /// <summary>Resolves a passphrase from the flag, environment variable, piped stdin, or a hidden prompt, in that order.</summary>
    /// <param name="flag">The passphrase supplied on the command line, or <c>null</c>.</param>
    /// <param name="label">The label shown when prompting interactively.</param>
    /// <returns>The resolved passphrase, or <c>null</c> if none was available.</returns>
    public static string? Resolve(string? flag, string label) {
        string? env;

        if (!string.IsNullOrEmpty(flag)) {
            return flag;
        }

        env = Environment.GetEnvironmentVariable(EnvVarName);
        if (!string.IsNullOrEmpty(env)) {
            return env;
        }

        if (!Interactive) {
            return null;
        }

        if (Console.IsInputRedirected) {
            string? line;

            line = Console.In.ReadLine();
            return string.IsNullOrEmpty(line) ? null : line;
        }

        return ReadHidden(label);
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
