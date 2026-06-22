using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Kems;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ScepWright.Server;

// RFC 9629 ML-KEM CMS decrypt path, self-contained so ScepWright.Server has no dependency on the
// ScepWright crypto libraries. Mirrors the decrypt half of
// ScepWright.Crypto.BouncyCastle.BcKemEnvelope / BcKemRecipientInfo (the encrypt half lives there and
// is exercised by its own tests). BouncyCastle 2.6.x exposes no CMS-level KEM recipient, so the CMS is
// parsed by hand. Profile: HKDF-SHA256 KDF, AES-256 key unwrap (RFC 3394).
internal static class KemEnvelopeDecrypt {
    // id-ori-kem { 1.2.840.113549.1.9.16.13.3 }
    private static readonly DerObjectIdentifier IdOriKem = new DerObjectIdentifier("1.2.840.113549.1.9.16.13.3");
    // id-ct-authEnvelopedData { 1.2.840.113549.1.9.16.1.23 }
    private static readonly DerObjectIdentifier IdCtAuthEnvelopedData = new DerObjectIdentifier("1.2.840.113549.1.9.16.1.23");

    // Decrypt either EnvelopedData (CBC) or AuthEnvelopedData (GCM), auto-detected by content type.
    public static byte[] Decrypt(byte[] der, MLKemPrivateKeyParameters recipient_private) {
        ContentInfo content_info;
        DerObjectIdentifier content_type;

        content_info = ContentInfo.GetInstance(Asn1Object.FromByteArray(der));
        content_type = content_info.ContentType;

        if (CmsObjectIdentifiers.EnvelopedData.Equals(content_type)) { return DecryptCbc(content_info, recipient_private); }
        if (IdCtAuthEnvelopedData.Equals(content_type)) { return DecryptGcm(content_info, recipient_private); }
        throw new InvalidOperationException("Unsupported CMS content type: " + content_type);
    }

    private static byte[] DecryptCbc(ContentInfo content_info, MLKemPrivateKeyParameters recipient_private) {
        EnvelopedData enveloped_data;
        Asn1Sequence kem_ri;
        byte[] cek;
        EncryptedContentInfo eci;
        byte[] iv;
        byte[] encrypted_content;
        byte[] plaintext;

        enveloped_data = EnvelopedData.GetInstance(content_info.Content);
        kem_ri = FindKemRecipient(enveloped_data.RecipientInfos) ?? throw new InvalidOperationException("No id-ori-kem recipient");
        cek = RecoverCek(kem_ri, recipient_private);

        eci = enveloped_data.EncryptedContentInfo;
        iv = Asn1OctetString.GetInstance(eci.ContentEncryptionAlgorithm.Parameters).GetOctets();
        if (eci.EncryptedContent is null) {
            throw new InvalidOperationException("EnvelopedData has no EncryptedContent ([0] OPTIONAL; detached content not supported)");
        }
        encrypted_content = eci.EncryptedContent.GetOctets();
        plaintext = AesCbc(false, cek, iv, encrypted_content);
        Array.Clear(cek, 0, cek.Length);
        return plaintext;
    }

    private static byte[] DecryptGcm(ContentInfo content_info, MLKemPrivateKeyParameters recipient_private) {
        Asn1Sequence auth_env;
        int idx;
        Asn1Set recipient_infos;
        EncryptedContentInfo eci;
        byte[] tag;
        Asn1Sequence kem_ri;
        byte[] cek;
        Asn1Sequence gcm_params;
        byte[] nonce;
        int icv_len;
        byte[] ciphertext;
        byte[] cipher_with_tag;
        byte[] plaintext;

        auth_env = Asn1Sequence.GetInstance(content_info.Content);
        idx = 0;
        idx++;   // version
        if (auth_env[idx] is Asn1TaggedObject t0 && t0.TagNo == 0) { idx++; }   // originatorInfo [0]
        recipient_infos = Asn1Set.GetInstance(auth_env[idx++]);
        eci = EncryptedContentInfo.GetInstance(auth_env[idx++]);
        if (auth_env[idx] is Asn1TaggedObject t1 && t1.TagNo == 1) { idx++; }   // authAttrs [1]
        tag = Asn1OctetString.GetInstance(auth_env[idx++]).GetOctets();

        kem_ri = FindKemRecipient(recipient_infos) ?? throw new InvalidOperationException("No id-ori-kem recipient");
        cek = RecoverCek(kem_ri, recipient_private);

        gcm_params = Asn1Sequence.GetInstance(eci.ContentEncryptionAlgorithm.Parameters);
        nonce = Asn1OctetString.GetInstance(gcm_params[0]).GetOctets();
        icv_len = gcm_params.Count > 1 ? DerInteger.GetInstance(gcm_params[1]).IntValueExact : 12;
        if (eci.EncryptedContent is null) {
            throw new InvalidOperationException("AuthEnvelopedData has no EncryptedContent ([0] OPTIONAL; detached content not supported)");
        }
        ciphertext = eci.EncryptedContent.GetOctets();

        cipher_with_tag = new byte[ciphertext.Length + tag.Length];
        Array.Copy(ciphertext, 0, cipher_with_tag, 0, ciphertext.Length);
        Array.Copy(tag, 0, cipher_with_tag, ciphertext.Length, tag.Length);
        plaintext = AesGcm(false, cek, nonce, cipher_with_tag, icv_len);
        Array.Clear(cek, 0, cek.Length);
        return plaintext;
    }

    // Recover the CEK from a KEMRecipientInfo SEQUENCE (the oriValue) with the recipient ML-KEM key.
    private static byte[] RecoverCek(Asn1Sequence kem_recipient_info, MLKemPrivateKeyParameters recipient_private_key) {
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

    private static Asn1Sequence? FindKemRecipient(Asn1Set recipient_infos) {
        foreach (Asn1Encodable element in recipient_infos) {
            Asn1Object obj;

            obj = element.ToAsn1Object();
            if (obj is Asn1TaggedObject tagged && tagged.TagNo == 4) {
                Asn1Sequence ori;
                DerObjectIdentifier ori_type;

                ori = Asn1Sequence.GetInstance(tagged, false);
                ori_type = DerObjectIdentifier.GetInstance(ori[0]);
                if (IdOriKem.Equals(ori_type)) { return Asn1Sequence.GetInstance(ori[1]); }
            }
        }
        return null;
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

    private static byte[] AesCbc(bool encrypt, byte[] key, byte[] iv, byte[] input) {
        IBufferedCipher cipher;

        cipher = CipherUtilities.GetCipher("AES/CBC/PKCS7Padding");
        cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
        return cipher.DoFinal(input);
    }

    private static byte[] AesGcm(bool encrypt, byte[] key, byte[] nonce, byte[] input, int tag_len_bytes) {
        IBufferedCipher cipher;
        AeadParameters parameters;

        cipher = CipherUtilities.GetCipher("AES/GCM/NoPadding");
        parameters = new AeadParameters(new KeyParameter(key), tag_len_bytes * 8, nonce);
        cipher.Init(encrypt, parameters);
        return cipher.DoFinal(input);
    }

    // RFC 3394 AES Key Unwrap. Use AesWrapEngine directly ("AES" via WrapperUtilities resolves to an
    // ECB-padding wrapper, which is NOT key-wrap and is non-interoperable).
    private static byte[] AesKeyUnwrap(byte[] kek, byte[] wrapped) {
        IWrapper wrapper;

        wrapper = new Org.BouncyCastle.Crypto.Engines.AesWrapEngine();
        wrapper.Init(false, new KeyParameter(kek));
        return wrapper.Unwrap(wrapped, 0, wrapped.Length);
    }
}
