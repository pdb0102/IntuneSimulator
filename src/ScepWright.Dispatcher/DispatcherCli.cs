using System;
using System.IO;
using ScepWright.Client;
using ScepWright.Core.Storage;
using ScepWright.Server.Host;

namespace ScepWright.Dispatcher;

/// <summary>Top-level <c>scepwright</c> dispatcher that routes to the client, test and server sub-tools.</summary>
public static class DispatcherCli {
    /// <summary>Dispatches the unified <c>scepwright</c> command line to the matching sub-tool and returns a process exit code.</summary>
    /// <param name="args">The command-line arguments, beginning with the sub-tool verb (<c>client</c>, <c>test</c> or <c>server</c>).</param>
    /// <param name="output">The writer that receives command output.</param>
    /// <returns>A process exit code: 0 on success, non-zero on failure.</returns>
    public static int Run(string[] args, TextWriter output) {
        string verb;
        string[] rest;
        string data_root;

        if (args == null || args.Length == 0) {
            output.WriteLine(UnifiedHelp());
            return 0;
        }

        verb = args[0];
        rest = new string[args.Length - 1];
        Array.Copy(args, 1, rest, 0, rest.Length);

        switch (verb) {
            case "client":
                if (IsHelp(rest)) {
                    output.WriteLine(CommandRouter.HelpUse());
                    return 0;
                }
                data_root = DataRoot.Resolve(GetFlag(rest, "--data-dir"));
                return CommandRouter.Run(rest, data_root, output);

            case "test":
                if (IsHelp(rest)) {
                    output.WriteLine(CommandRouter.HelpTest());
                    return 0;
                }
                data_root = DataRoot.Resolve(GetFlag(rest, "--data-dir"));
                return CommandRouter.Run(rest, data_root, output);

            case "server":
                if (rest.Length > 0 && (rest[0] == "help" || rest[0] == "--help" || rest[0] == "-h")) {
                    output.WriteLine(ServerCli.Help("scepwright server"));
                    return 0;
                }
                return ServerCli.Run(rest, output);

            case "help":
            case "--help":
            case "-h":
                output.WriteLine(UnifiedHelp());
                return 0;

            case "version":
            case "--version":
                output.WriteLine($"scepwright {Version()}");
                return 0;

            default:
                output.WriteLine($"unknown command '{verb}'");
                output.WriteLine();
                output.WriteLine(UnifiedHelp());
                return 2;
        }
    }

    private static string Version() {
        System.Reflection.Assembly asm;
        System.Reflection.AssemblyInformationalVersionAttribute? info;

        asm = typeof(DispatcherCli).Assembly;
        info = System.Reflection.CustomAttributeExtensions.GetCustomAttribute<System.Reflection.AssemblyInformationalVersionAttribute>(asm);
        return string.IsNullOrEmpty(info?.InformationalVersion) ? (asm.GetName().Version?.ToString() ?? "unknown") : info!.InformationalVersion;
    }

    private static string UnifiedHelp() {
        return string.Join('\n', new[] {
            "scepwright — SCEP testing suite (one tool over the scepclient + scepca engines).",
            "",
            "Usage: scepwright <client|test|server> [args]",
            "       scepwright help",
            "",
            "  client <args>   get and manage real certificates",
            "  test <args>     exercise a SCEP server for RFC 8894 compliance",
            "  server <args>   run the built-in SCEP server (real certs from an UNTRUSTED test CA)",
            "",
            CommandRouter.HelpUse("scepwright client"),
            "",
            CommandRouter.HelpTest("scepwright test"),
            "",
            ServerCli.Help("scepwright server"),
        });
    }

    private static bool IsHelp(string[] rest) {
        if (rest.Length == 0) {
            return true;
        }
        return rest[0] == "help" || rest[0] == "--help" || rest[0] == "-h";
    }

    private static string? GetFlag(string[] args, string name) {
        int i;

        for (i = 0; i < args.Length - 1; i++) {
            if (args[i] == name) {
                return args[i + 1];
            }
        }
        return null;
    }
}
