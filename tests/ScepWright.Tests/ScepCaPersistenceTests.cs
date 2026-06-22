using System;
using System.IO;
using ScepWright.Server;
using Xunit;

namespace ScepWright.Tests;

public sealed class ScepCaPersistenceTests {
    [Theory]
    [InlineData("rsa")]
    [InlineData("ml-dsa")]
    public void Single_ca_persist_load_preserves_cert(string algo) {
        string dir;
        ScepCa original;
        ScepCa loaded;

        dir = Path.Combine(Path.GetTempPath(), $"scepca-persist-{Guid.NewGuid():N}");
        original = ScepCa.Create(algo);
        try {
            Directory.CreateDirectory(dir);
            original.Persist(dir);
            loaded = ScepCa.LoadFrom(dir);
            Assert.Equal(original.CertificateBcl.RawData, loaded.CertificateBcl.RawData);
            Assert.True(loaded.BuildCaCertBundleDer().Length > 0);
        } finally {
            if (Directory.Exists(dir)) { Directory.Delete(dir, true); }
        }
    }

    [Fact]
    public void Split_ra_ca_persist_load_preserves_both_certs() {
        string dir;
        ScepCa original;
        ScepCa loaded;

        dir = Path.Combine(Path.GetTempPath(), $"scepca-persist-{Guid.NewGuid():N}");
        original = ScepCa.CreateWithRaEncryption("ml-kem");
        try {
            Directory.CreateDirectory(dir);
            original.Persist(dir);
            loaded = ScepCa.LoadFrom(dir);
            Assert.Equal(original.CertificateBcl.RawData, loaded.CertificateBcl.RawData);
            Assert.NotNull(loaded.EncryptionCert);
            Assert.Equal(original.EncryptionCert!.RawData, loaded.EncryptionCert!.RawData);
        } finally {
            if (Directory.Exists(dir)) { Directory.Delete(dir, true); }
        }
    }

    [Fact]
    public void Encrypted_persist_writes_enc_file_and_no_plaintext_and_round_trips() {
        string dir;
        ScepCa original;
        ScepCa loaded;

        dir = Path.Combine(Path.GetTempPath(), $"scepca-enc-{Guid.NewGuid():N}");
        original = ScepCa.Create("rsa");
        try {
            Directory.CreateDirectory(dir);
            original.Persist(dir, "s3cr3t-pass");
            Assert.True(File.Exists(Path.Combine(dir, "ca.key.pkcs8.enc")), "encrypted key file must exist");
            Assert.False(File.Exists(Path.Combine(dir, "ca.key.pkcs8")), "plaintext key file must NOT exist");
            loaded = ScepCa.LoadFrom(dir, "s3cr3t-pass");
            Assert.Equal(original.CertificateBcl.RawData, loaded.CertificateBcl.RawData);
            Assert.True(loaded.BuildCaCertBundleDer().Length > 0);
        } finally {
            if (Directory.Exists(dir)) { Directory.Delete(dir, true); }
        }
    }

    [Fact]
    public void Encrypted_split_ra_persist_writes_ra_enc_file_and_round_trips() {
        string dir;
        ScepCa original;
        ScepCa loaded;

        dir = Path.Combine(Path.GetTempPath(), $"scepca-enc-ra-{Guid.NewGuid():N}");
        original = ScepCa.CreateWithRaEncryption("rsa", "rsa");
        try {
            Directory.CreateDirectory(dir);
            original.Persist(dir, "ra-pass");
            Assert.True(File.Exists(Path.Combine(dir, "ca.key.pkcs8.enc")), "encrypted CA key file must exist");
            Assert.True(File.Exists(Path.Combine(dir, "ra.key.pkcs8.enc")), "encrypted RA key file must exist");
            Assert.False(File.Exists(Path.Combine(dir, "ra.key.pkcs8")), "plaintext RA key file must NOT exist");
            loaded = ScepCa.LoadFrom(dir, "ra-pass");
            Assert.Equal(original.CertificateBcl.RawData, loaded.CertificateBcl.RawData);
            Assert.NotNull(loaded.EncryptionCert);
            Assert.Equal(original.EncryptionCert!.RawData, loaded.EncryptionCert!.RawData);
        } finally {
            if (Directory.Exists(dir)) { Directory.Delete(dir, true); }
        }
    }

    [Fact]
    public void Encrypted_load_with_wrong_passphrase_fails_cleanly() {
        string dir;
        ScepCa original;

        dir = Path.Combine(Path.GetTempPath(), $"scepca-enc-wrong-{Guid.NewGuid():N}");
        original = ScepCa.Create("rsa");
        try {
            Directory.CreateDirectory(dir);
            original.Persist(dir, "right-pass");
            Assert.Throws<CaKeyProtectionException>(() => ScepCa.LoadFrom(dir, "wrong-pass"));
            Assert.Throws<CaKeyProtectionException>(() => ScepCa.LoadFrom(dir, null));
        } finally {
            if (Directory.Exists(dir)) { Directory.Delete(dir, true); }
        }
    }

    [Fact]
    public void Load_or_create_is_stable_across_runs() {
        string root;
        System.Collections.Generic.Dictionary<string, ScepCa> first;
        System.Collections.Generic.Dictionary<string, ScepCa> second;

        root = Path.Combine(Path.GetTempPath(), $"scepca-root-{Guid.NewGuid():N}");
        try {
            first = ScepServerApp.LoadOrCreateProfiles(root);
            second = ScepServerApp.LoadOrCreateProfiles(root);
            foreach (string name in first.Keys) {
                Assert.Equal(first[name].CertificateBcl.RawData, second[name].CertificateBcl.RawData);
            }
        } finally {
            if (Directory.Exists(root)) { Directory.Delete(root, true); }
        }
    }
}
