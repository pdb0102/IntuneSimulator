using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Utilities.Collections;
using ScepWright.Crypto;
using ScepWright.Crypto.BouncyCastle;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

// When a CertRep signature can't be verified the client must say WHO claimed to sign it and WHAT cert it
// checked — and try the GetCACert bundle — so a server-implementor can tell a genuinely invalid signature
// from "the signer cert simply wasn't embedded in the CertRep, so we looked in the wrong place".
public class CertRepSignatureDiagnosticsTests {
    private static byte[] BuildCertRep(out BouncyCastleScepCrypto crypto, out ScepCa ca, out IScepKey client_key) {
        KeySpec spec;
        Pkcs10 csr;
        byte[] csr_der;
        Pkcs10CertificationRequest parsed;
        Org.BouncyCastle.X509.X509Certificate issued;
        X509Certificate2 client_cert;

        crypto = new BouncyCastleScepCrypto();
        ca = ScepCa.Create();
        KeySpec.Parse("rsa:2048", out spec, out _);
        crypto.GenerateKey(spec, out client_key, out _);
        csr = new Pkcs10 { Key = client_key };
        csr.SetSubject("CN=poodle", out _);
        crypto.EncodeCsr(csr, out csr_der, out _);
        parsed = new Pkcs10CertificationRequest(csr_der);
        issued = ca.Issue(parsed.GetPublicKey(), "CN=poodle");
        client_cert = new X509Certificate2(issued.GetEncoded());
        return ca.BuildSuccessCertRep(issued, client_cert, "tx", new byte[16]);
    }

    private static byte[] StripCertificates(byte[] cert_rep) {
        CmsSignedData signed;
        IStore<Org.BouncyCastle.X509.X509Certificate> empty;

        signed = new CmsSignedData(cert_rep);
        empty = CollectionUtilities.CreateStore(new List<Org.BouncyCastle.X509.X509Certificate>());
        return CmsSignedData.ReplaceCertificatesAndCrls(signed, empty, null).GetEncoded();
    }

    [Fact]
    public void Decode_reports_the_claimed_signer_and_verifies_a_normal_certrep() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
        IScepKey client_key;
        byte[] cert_rep;
        PkiMessage msg;
        string error;

        cert_rep = BuildCertRep(out crypto, out ca, out client_key);

        Assert.True(crypto.DecodePkiMessage(cert_rep, client_key, CodecOptions.LenientParsing, null, out msg, out error), error);
        Assert.True(msg.SignatureValid);
        Assert.False(string.IsNullOrEmpty(msg.SignerClaimedIdentity));
    }

    [Fact]
    public void Absent_signer_cert_verified_via_GetCACert_raises_no_finding() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
        IScepKey client_key;
        byte[] cert_rep;
        byte[] stripped;
        PkiMessage without;
        PkiMessage with;
        string error;
        string notes;

        cert_rep = BuildCertRep(out crypto, out ca, out client_key);
        stripped = StripCertificates(cert_rep);

        // No certs embedded and no known certs -> can't verify (no bundle to fall back to).
        Assert.True(crypto.DecodePkiMessage(stripped, client_key, CodecOptions.LenientParsing, null, out without, out error), error);
        Assert.False(without.SignatureValid);

        // Hand it the GetCACert bundle -> it verifies against the trusted CA cert. Omitting the signer cert
        // is permitted (CMS makes it optional; it's distributed via GetCACert), so there is NO finding.
        Assert.True(crypto.DecodePkiMessage(stripped, client_key, CodecOptions.LenientParsing, new[] { ca.CertificateBcl }, out with, out error), error);
        Assert.True(with.SignatureValid);
        Assert.Equal(without.SignerClaimedIdentity, with.SignerClaimedIdentity);

        notes = string.Join(" ", with.ConformanceNotes.ConvertAll(n => n.What));
        Assert.DoesNotContain("signature", notes);
    }

    [Fact]
    public void Valid_signature_by_a_cert_not_in_the_CA_bundle_raises_a_finding() {
        BouncyCastleScepCrypto crypto;
        ScepCa signing_ca;
        ScepCa other_ca;
        IScepKey client_key;
        byte[] cert_rep;
        PkiMessage msg;
        string error;
        string notes;

        // The CertRep is signed by (and embeds) signing_ca's cert, but we hand decode a DIFFERENT CA bundle.
        cert_rep = BuildCertRep(out crypto, out signing_ca, out client_key);
        other_ca = ScepCa.Create();

        Assert.True(crypto.DecodePkiMessage(cert_rep, client_key, CodecOptions.LenientParsing, new[] { other_ca.CertificateBcl }, out msg, out error), error);

        // The signature is cryptographically valid (verified against the embedded signer cert)...
        Assert.True(msg.SignatureValid);
        // ...but the signer is not the CA/RA the client trusts, so we MUST flag it.
        notes = string.Join(" ", msg.ConformanceNotes.ConvertAll(n => n.What));
        Assert.Contains("not", notes.ToLowerInvariant());
        Assert.Contains("GetCACert", notes);
    }

    [Fact]
    public void Unverifiable_signature_note_names_the_claimed_signer_and_what_was_tried() {
        BouncyCastleScepCrypto crypto;
        ScepCa ca;
        IScepKey client_key;
        byte[] cert_rep;
        byte[] stripped;
        PkiMessage msg;
        string error;
        string notes;

        cert_rep = BuildCertRep(out crypto, out ca, out client_key);
        stripped = StripCertificates(cert_rep);

        // Stripped of certs, with an unrelated cert as the only candidate -> nothing verifies.
        Assert.True(crypto.DecodePkiMessage(stripped, client_key, CodecOptions.LenientParsing, null, out msg, out error), error);
        Assert.False(msg.SignatureValid);

        notes = string.Join(" ", msg.ConformanceNotes.ConvertAll(n => n.What));
        Assert.Contains("claimed signer", notes);
        Assert.Contains(msg.SignerClaimedIdentity!, notes);
    }
}
