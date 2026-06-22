namespace ScepWright.Crypto;

/// <summary>A parsed key-generation specification: algorithm family plus its size or parameter set.</summary>
public sealed class KeySpec {
    private static readonly string[] MlDsaSets = { "44", "65", "87" };
    // SLH-DSA (FIPS 205) SHA2 family, both small (s) and fast (f). A bare set token maps to the
    // SHA2 variant; the SHAKE family would need a distinct token scheme and is not exposed here.
    private static readonly string[] SlhDsaSets = { "128s", "128f", "192s", "192f", "256s", "256f" };
    private static readonly string[] EcCurves = { "p256", "p384", "p521" };

    /// <summary>Gets the algorithm family (RSA, EC, ML-DSA, SLH-DSA).</summary>
    public string Algorithm { get; }
    /// <summary>Gets the key size in bits (RSA modulus / EC curve size); 0 for PQ algorithms.</summary>
    public int Size { get; }
    /// <summary>Gets the parameter token (EC curve name or PQ parameter set); empty for RSA.</summary>
    public string Parameter { get; }

    private KeySpec(string algorithm, int size, string parameter) {
        Algorithm = algorithm;
        Size = size;
        Parameter = parameter;
    }

    /// <summary>
    /// Parses a key specification of the form <c>rsa:&lt;bits&gt;</c> (bits ≥ 1024),
    /// <c>ec:p256|p384|p521</c>, <c>ml-dsa:44|65|87</c>, or <c>slh-dsa:&lt;set&gt;</c>
    /// (128s/128f/192s/192f/256s/256f). The algorithm token is case-insensitive. ML-KEM is rejected:
    /// a key-encapsulation algorithm cannot be a certificate subject key.
    /// </summary>
    public static bool Parse(string text, out KeySpec spec, out string error) {
        string[] parts;
        string algo;
        string param;
        int bits;

        spec = null!;
        error = string.Empty;

        if (string.IsNullOrWhiteSpace(text)) {
            error = "key spec is empty";
            return false;
        }

        parts = text.Split(':');
        if (parts.Length != 2) {
            error = $"unsupported key spec '{text}' (expected 'rsa:<bits>' / 'ec:p256' / 'ml-dsa:<set>' / 'slh-dsa:<set>')";
            return false;
        }

        algo = parts[0].ToLowerInvariant();
        param = parts[1];

        if (algo == "rsa") {
            if (!int.TryParse(param, out bits) || bits < 1024) {
                error = $"invalid RSA size in '{text}'";
                return false;
            }
            spec = new KeySpec("RSA", bits, string.Empty);
            return true;
        }

        if (algo == "ml-dsa") {
            if (System.Array.IndexOf(MlDsaSets, param) < 0) {
                error = $"invalid ML-DSA parameter set '{param}' (expected 44/65/87)";
                return false;
            }
            spec = new KeySpec("ML-DSA", 0, param);
            return true;
        }

        if (algo == "slh-dsa") {
            if (System.Array.IndexOf(SlhDsaSets, param) < 0) {
                error = $"invalid SLH-DSA parameter set '{param}'";
                return false;
            }
            spec = new KeySpec("SLH-DSA", 0, param);
            return true;
        }

        if (algo == "ml-kem") {
            // ML-KEM is a key-encapsulation mechanism, not a signature scheme, so it cannot be a
            // certificate subject key — reject it here rather than minting a key that only fails at enroll.
            // (ML-KEM is still usable as a recipient/encryption algorithm; that path does not use KeySpec.)
            error = "ML-KEM cannot be used as a certificate subject key (it is a key-encapsulation algorithm, not a signature scheme); it is only valid as a recipient/encryption algorithm";
            return false;
        }

        if (algo == "ec") {
            int curve_bits;

            if (System.Array.IndexOf(EcCurves, param) < 0) {
                error = $"invalid EC curve '{param}' (expected p256/p384/p521)";
                return false;
            }
            curve_bits = param == "p256" ? 256 : param == "p384" ? 384 : 521;
            spec = new KeySpec("EC", curve_bits, param);
            return true;
        }

        error = $"unsupported key spec '{text}'";
        return false;
    }
}
