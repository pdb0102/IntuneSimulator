using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;

namespace ScepWright.Crypto.BouncyCastle;

// RFC 9629 KEMRecipientInfo for ML-KEM, hand-rolled because BouncyCastle 2.6.x does not expose a
// CMS-level KEM recipient generator. Profile: HKDF-SHA256 KDF, AES-256 key wrap.
internal static class BcKemRecipientInfo {
    // id-ori-kem { 1.2.840.113549.1.9.16.13.3 }
    private static readonly DerObjectIdentifier IdOriKem = new DerObjectIdentifier("1.2.840.113549.1.9.16.13.3");
    // id-alg-hkdf-with-sha256 { 1.2.840.113549.1.9.16.3.28 } (RFC 8619)
    private static readonly DerObjectIdentifier IdAlgHkdfWithSha256 = new DerObjectIdentifier("1.2.840.113549.1.9.16.3.28");
    private static readonly DerObjectIdentifier IdAes256Wrap = NistObjectIdentifiers.IdAes256Wrap;

    private const int KekLengthBytes = 32;   // AES-256 KEK

    // Encrypt side: wrap the caller's content-encryption key (CEK) for an ML-KEM recipient and return
    // a fully-encoded KEMRecipientInfo carried as OtherRecipientInfo ([4]).
    public static RecipientInfo CreateRecipientInfo(byte[] cek, MLKemPublicKeyParameters recipient_public_key, byte[] recipient_key_id, byte[]? ukm) {
        MLKemEncapsulator encapsulator;
        MLKemParameters kem_parameters;
        byte[] shared_secret;
        byte[] kem_ciphertext;
        AlgorithmIdentifier kem_alg_id;
        AlgorithmIdentifier kdf_alg_id;
        AlgorithmIdentifier wrap_alg_id;
        byte[] other_info;
        byte[] kek;
        byte[] wrapped_cek;
        Asn1EncodableVector v;
        DerSequence kem_recipient_info;
        Asn1EncodableVector ori;

        kem_parameters = recipient_public_key.Parameters;
        encapsulator = new MLKemEncapsulator(kem_parameters);
        encapsulator.Init(recipient_public_key);
        kem_ciphertext = new byte[encapsulator.EncapsulationLength];
        shared_secret = new byte[encapsulator.SecretLength];
        encapsulator.Encapsulate(kem_ciphertext, 0, kem_ciphertext.Length, shared_secret, 0, shared_secret.Length);

        kem_alg_id = new AlgorithmIdentifier(KemOidFor(kem_parameters));
        kdf_alg_id = new AlgorithmIdentifier(IdAlgHkdfWithSha256);   // HKDF-SHA256: parameters absent
        wrap_alg_id = new AlgorithmIdentifier(IdAes256Wrap);

        other_info = EncodeOtherInfo(wrap_alg_id, KekLengthBytes, ukm);
        kek = HkdfDerive(shared_secret, other_info, KekLengthBytes);
        wrapped_cek = AesKeyWrap(kek, cek);

        Array.Clear(shared_secret, 0, shared_secret.Length);
        Array.Clear(kek, 0, kek.Length);

        v = new Asn1EncodableVector();
        v.Add(new DerInteger(0));                                                  // version
        v.Add(new DerTaggedObject(false, 0, new DerOctetString(recipient_key_id)));// rid: subjectKeyIdentifier [0]
        v.Add(kem_alg_id);                                                          // kem
        v.Add(new DerOctetString(kem_ciphertext));                                 // kemct
        v.Add(kdf_alg_id);                                                          // kdf
        v.Add(new DerInteger(KekLengthBytes));                                      // kekLength
        if (ukm != null) {
            v.Add(new DerTaggedObject(true, 0, new DerOctetString(ukm)));          // ukm [0] EXPLICIT OPTIONAL
        }
        v.Add(wrap_alg_id);                                                         // wrap
        v.Add(new DerOctetString(wrapped_cek));                                     // encryptedKey

        kem_recipient_info = new DerSequence(v);

        // OtherRecipientInfo ::= SEQUENCE { oriType OID, oriValue ANY }
        ori = new Asn1EncodableVector();
        ori.Add(IdOriKem);
        ori.Add(kem_recipient_info);

        // RecipientInfo ::= CHOICE { ... ori [4] IMPLICIT OtherRecipientInfo }
        return RecipientInfo.GetInstance(new DerTaggedObject(false, 4, new DerSequence(ori)));
    }

    // Decrypt side: recover the CEK from a KEMRecipientInfo SEQUENCE (the oriValue) with the recipient
    // ML-KEM private key.
    public static byte[] RecoverCek(Asn1Sequence kem_recipient_info, MLKemPrivateKeyParameters recipient_private_key) {
        int idx;
        byte[] kem_ciphertext;
        int kek_length;
        byte[]? ukm;
        AlgorithmIdentifier wrap_alg_id;
        byte[] wrapped_cek;
        MLKemDecapsulator decapsulator;
        byte[] shared_secret;
        byte[] other_info;
        byte[] kek;
        byte[] cek;

        ukm = null;
        idx = 0;
        idx++;   // version
        idx++;   // rid (recipient already selected by key id)
        idx++;   // kem AlgorithmIdentifier (param set fixed by the key)
        kem_ciphertext = Asn1OctetString.GetInstance(kem_recipient_info[idx++]).GetOctets();
        idx++;   // kdf AlgorithmIdentifier (assume HKDF-SHA256 per profile)
        kek_length = DerInteger.GetInstance(kem_recipient_info[idx++]).IntValueExact;

        if (kem_recipient_info[idx] is Asn1TaggedObject tagged && tagged.TagNo == 0) {
            ukm = Asn1OctetString.GetInstance(tagged.GetExplicitBaseObject()).GetOctets();
            idx++;
        }

        wrap_alg_id = AlgorithmIdentifier.GetInstance(kem_recipient_info[idx++]);
        wrapped_cek = Asn1OctetString.GetInstance(kem_recipient_info[idx++]).GetOctets();

        decapsulator = new MLKemDecapsulator(recipient_private_key.Parameters);
        decapsulator.Init(recipient_private_key);
        shared_secret = new byte[decapsulator.SecretLength];
        decapsulator.Decapsulate(kem_ciphertext, 0, kem_ciphertext.Length, shared_secret, 0, shared_secret.Length);
        other_info = EncodeOtherInfo(wrap_alg_id, kek_length, ukm);
        kek = HkdfDerive(shared_secret, other_info, kek_length);
        cek = AesKeyUnwrap(kek, wrapped_cek);

        Array.Clear(shared_secret, 0, shared_secret.Length);
        Array.Clear(kek, 0, kek.Length);
        return cek;
    }

    // CMSORIforKEMOtherInfo ::= SEQUENCE { wrap KeyEncryptionAlgorithmIdentifier,
    //   kekLength INTEGER (1..65535), ukm [0] EXPLICIT UserKeyingMaterial OPTIONAL }
    private static byte[] EncodeOtherInfo(AlgorithmIdentifier wrap_alg_id, int kek_length, byte[]? ukm) {
        Asn1EncodableVector v;

        v = new Asn1EncodableVector();
        v.Add(wrap_alg_id);
        v.Add(new DerInteger(kek_length));
        if (ukm != null) {
            v.Add(new DerTaggedObject(true, 0, new DerOctetString(ukm)));
        }
        return new DerSequence(v).GetDerEncoded();
    }

    private static byte[] HkdfDerive(byte[] ikm, byte[] info, int length) {
        HkdfBytesGenerator hkdf;
        byte[] okm;

        hkdf = new HkdfBytesGenerator(new Sha256Digest());
        hkdf.Init(new HkdfParameters(ikm, new byte[0], info));   // RFC 9629: salt is the empty string
        okm = new byte[length];
        hkdf.GenerateBytes(okm, 0, length);
        return okm;
    }

    // RFC 3394 AES Key Wrap (what id-aesNNN-wrap denotes). "AES" via WrapperUtilities resolves to an
    // ECB-padding wrapper, which is NOT key-wrap and is non-interoperable — use AesWrapEngine directly.
    private static byte[] AesKeyWrap(byte[] kek, byte[] key_to_wrap) {
        IWrapper wrapper;

        wrapper = new Org.BouncyCastle.Crypto.Engines.AesWrapEngine();
        wrapper.Init(true, new KeyParameter(kek));
        return wrapper.Wrap(key_to_wrap, 0, key_to_wrap.Length);
    }

    private static byte[] AesKeyUnwrap(byte[] kek, byte[] wrapped) {
        IWrapper wrapper;

        wrapper = new Org.BouncyCastle.Crypto.Engines.AesWrapEngine();
        wrapper.Init(false, new KeyParameter(kek));
        return wrapper.Unwrap(wrapped, 0, wrapped.Length);
    }

    private static DerObjectIdentifier KemOidFor(MLKemParameters p) {
        if (p == MLKemParameters.ml_kem_512) { return NistObjectIdentifiers.id_alg_ml_kem_512; }
        if (p == MLKemParameters.ml_kem_768) { return NistObjectIdentifiers.id_alg_ml_kem_768; }
        if (p == MLKemParameters.ml_kem_1024) { return NistObjectIdentifiers.id_alg_ml_kem_1024; }
        throw new ArgumentException("Unsupported ML-KEM parameter set");
    }
}
