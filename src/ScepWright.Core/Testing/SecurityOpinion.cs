namespace ScepWright.Core.Testing;

/// <summary>A security verdict on an algorithm's strength.</summary>
public enum AlgorithmPosture {
    /// <summary>Must not be used (broken).</summary>
    MustNot,
    /// <summary>Legacy and weak; interop only.</summary>
    LegacyWeak,
    /// <summary>Currently acceptable.</summary>
    Modern,
    /// <summary>Post-quantum / forward-looking.</summary>
    CuttingEdge,
    /// <summary>Unrecognized.</summary>
    Unknown
}

/// <summary>Classifies digest, cipher, RSA, and signature algorithms by security posture.</summary>
public static class SecurityOpinion {
    /// <summary>Classifies a digest algorithm by name.</summary>
    public static AlgorithmPosture ClassifyDigest(string name) {
        switch ((name ?? string.Empty).ToUpperInvariant()) {
            case "MD5": return AlgorithmPosture.MustNot;
            case "SHA-1": return AlgorithmPosture.LegacyWeak;
            case "SHA-256":
            case "SHA-512": return AlgorithmPosture.Modern;
            default: return AlgorithmPosture.Unknown;
        }
    }

    /// <summary>Classifies a content-encryption cipher by name.</summary>
    public static AlgorithmPosture ClassifyCipher(string name) {
        switch ((name ?? string.Empty).ToUpperInvariant()) {
            case "DES":
            case "DES-CBC": return AlgorithmPosture.MustNot;
            case "DES-EDE3-CBC":
            case "DES3":
            case "3DES": return AlgorithmPosture.LegacyWeak;
            case "AES-128-CBC":
            case "AES-256-CBC":
            case "AES": return AlgorithmPosture.Modern;
            default: return AlgorithmPosture.Unknown;
        }
    }

    /// <summary>Classifies an RSA key by size against the configured minimum.</summary>
    public static AlgorithmPosture ClassifyRsa(int bits, OpinionThresholds thresholds) {
        if (bits < 1024) { return AlgorithmPosture.MustNot; }
        if (bits < thresholds.MinRsaKeyBits) { return AlgorithmPosture.LegacyWeak; }
        return AlgorithmPosture.Modern;
    }

    /// <summary>Classifies a signature/key algorithm by name (PQ families rate as cutting-edge).</summary>
    public static AlgorithmPosture ClassifySignature(string name) {
        string upper;

        upper = (name ?? string.Empty).ToUpperInvariant();
        if (upper.StartsWith("ML-DSA") || upper.StartsWith("SLH-DSA") || upper.StartsWith("ML-KEM")) {
            return AlgorithmPosture.CuttingEdge;
        }
        if (upper.StartsWith("EC")) { return AlgorithmPosture.Modern; }
        if (upper == "RSA") { return AlgorithmPosture.Modern; }
        return AlgorithmPosture.Unknown;
    }
}
