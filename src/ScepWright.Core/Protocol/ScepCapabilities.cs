using System;
using System.Collections.Generic;

namespace ScepWright.Core.Protocol;

/// <summary>The capability keywords a SCEP server advertises via its GetCACaps response.</summary>
public sealed class ScepCapabilities {
    /// <summary>Gets whether the server supports AES content encryption.</summary>
    public bool Aes { get; private set; }
    /// <summary>Gets whether the server supports 3DES content encryption.</summary>
    public bool Des3 { get; private set; }
    /// <summary>Gets whether the server supports GetNextCACert.</summary>
    public bool GetNextCaCert { get; private set; }
    /// <summary>Gets whether the server supports POST for PKIOperation.</summary>
    public bool PostPkiOperation { get; private set; }
    /// <summary>Gets whether the server supports renewal.</summary>
    public bool Renewal { get; private set; }
    /// <summary>Gets whether the server advertises SHA-1.</summary>
    public bool Sha1 { get; private set; }
    /// <summary>Gets whether the server advertises SHA-256.</summary>
    public bool Sha256 { get; private set; }
    /// <summary>Gets whether the server advertises SHA-512.</summary>
    public bool Sha512 { get; private set; }
    /// <summary>Gets any advertised keywords not recognized by this parser.</summary>
    public List<string> Unknown { get; } = new();
    /// <summary>Gets the raw capability keywords exactly as advertised.</summary>
    public string[] RawKeywords { get; private set; } = Array.Empty<string>();

    /// <summary>Parses a GetCACaps response body (one keyword per line) into a capability set.</summary>
    public static ScepCapabilities Parse(string text) {
        ScepCapabilities caps;
        List<string> raw;

        caps = new ScepCapabilities();
        raw = new List<string>();

        foreach (string line in (text ?? string.Empty).Split('\n')) {
            string kw;

            kw = line.Trim();
            if (kw.Length == 0) { continue; }
            raw.Add(kw);
            switch (kw.ToUpperInvariant()) {
                case "AES": caps.Aes = true; break;
                case "DES3": caps.Des3 = true; break;
                case "GETNEXTCACERT": caps.GetNextCaCert = true; break;
                case "POSTPKIOPERATION": caps.PostPkiOperation = true; break;
                case "RENEWAL": caps.Renewal = true; break;
                case "SHA-1": caps.Sha1 = true; break;
                case "SHA-256": caps.Sha256 = true; break;
                case "SHA-512": caps.Sha512 = true; break;
                default: caps.Unknown.Add(kw); break;
            }
        }
        caps.RawKeywords = raw.ToArray();
        return caps;
    }
}
