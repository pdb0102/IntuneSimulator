using System;
using System.Security.Cryptography;
using System.Text;

namespace ScepWright.Core.Storage;

/// <summary>Helpers for redacting secrets before they are persisted or displayed.</summary>
public static class Redaction {
    /// <summary>Returns a <c>sha256:</c>-prefixed hex digest of the value, for storing without the plaintext.</summary>
    public static string Hash(string sensitive) {
        byte[] digest;

        digest = SHA256.HashData(Encoding.UTF8.GetBytes(sensitive ?? string.Empty));
        return "sha256:" + Convert.ToHexString(digest).ToLowerInvariant();
    }
}
