using Org.BouncyCastle.Pkcs;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Crypto;
using Xunit;

namespace ScepWright.Tests;

public sealed class PqCsrTests {
    [Fact]
    public void Ml_dsa_csr_parses_and_verifies() {
        BouncyCastleScepCrypto crypto;
        KeySpec spec;
        IScepKey key;
        Pkcs10 csr;
        byte[] der;
        string error;
        Pkcs10CertificationRequest parsed;

        crypto = new BouncyCastleScepCrypto();
        Assert.True(KeySpec.Parse("ml-dsa:65", out spec, out error), error);
        Assert.True(crypto.GenerateKey(spec, out key, out error), error);

        csr = new Pkcs10 { Key = key, ChallengePassword = "pw" };
        csr.SetSubject("CN=pq-test", out error);
        Assert.True(crypto.EncodeCsr(csr, out der, out error), error);

        parsed = new Pkcs10CertificationRequest(der);
        Assert.True(parsed.Verify());
        Assert.Contains("2.16.840.1.101.3.4.3.18",
            parsed.GetCertificationRequestInfo().SubjectPublicKeyInfo.Algorithm.Algorithm.Id);
    }
}
