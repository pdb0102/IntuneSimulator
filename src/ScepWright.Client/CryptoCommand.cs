using System.Collections.Generic;
using System.IO;
using ScepWright.Core;
using ScepWright.Crypto;

namespace ScepWright.Client;

internal static class CryptoCommand {
    public static int Run(string[] args, string data_root, TextWriter output) {
        string verb;
        string? provider_path;
        IScepCrypto crypto;
        string error;

        if (args.Length < 2) {
            output.WriteLine("usage: crypto <info|list>");
            return 2;
        }
        verb = args[1];
        provider_path = CommandRouter.ResolveProviderPath(args, data_root);

        if (ScepCrypto.Load(provider_path, out crypto, out error) != ScepClientResult.Ok) {
            output.WriteLine($"crypto load error: {error}");
            return 1;
        }

        switch (verb) {
            case "list":
                return List(crypto, output);

            case "info":
                return Info(crypto, provider_path, output);

            default:
                output.WriteLine("usage: crypto <info|list>");
                return 2;
        }
    }

    private static int List(IScepCrypto crypto, TextWriter output) {
        PrintGroup(output, "Digests", crypto.Capabilities.Digests);
        PrintGroup(output, "Signatures", crypto.Capabilities.Signatures);
        PrintGroup(output, "ContentEncryption", crypto.Capabilities.ContentEncryption);
        PrintGroup(output, "KeyTransport", crypto.Capabilities.KeyTransport);
        PrintGroup(output, "KEM", crypto.Capabilities.Kem);
        PrintGroup(output, "AsymmetricKeys", crypto.Capabilities.AsymmetricKeys);
        return 0;
    }

    private static int Info(IScepCrypto crypto, string? provider_path, TextWriter output) {
        output.WriteLine(string.IsNullOrWhiteSpace(provider_path)
            ? "Provider: built-in (BouncyCastle)"
            : $"Provider: {provider_path}");
        output.WriteLine();
        output.WriteLine("Post-quantum support (tiers):");
        // Pad the description to a fixed width so the Yes/No column lines up across all three tiers
        // (Tier C's label is the longest, so a shorter A/B label must pad to match).
        output.WriteLine($"  Tier A  {"ML-DSA signatures (FIPS 204):",-48}{YesNo(crypto.Capabilities.PqTiers.TierA)}");
        output.WriteLine($"  Tier B  {"SLH-DSA signatures (FIPS 205):",-48}{YesNo(crypto.Capabilities.PqTiers.TierB)}");
        output.WriteLine($"  Tier C  {"ML-KEM enveloping, KEMRecipientInfo (RFC 9629):",-48}{YesNo(crypto.Capabilities.PqTiers.TierC)}");
        output.WriteLine();
        output.WriteLine("Run `crypto list` for the full digest / signature / encryption / key-transport / KEM inventory.");
        return 0;
    }

    private static string YesNo(bool value) => value ? "yes" : "no";

    private static void PrintGroup(TextWriter output, string title, IReadOnlyCollection<string> oids) {
        List<string> names;

        names = new List<string>();
        foreach (string oid in oids) {
            names.Add(Algorithms.NameFor(oid) ?? oid);
        }
        output.WriteLine($"{title}: {string.Join(", ", names)}");
    }
}
