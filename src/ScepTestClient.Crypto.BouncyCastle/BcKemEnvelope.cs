using System;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Cms;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace ScepTestClient.Crypto.BouncyCastle;

// CMS EnvelopedData (AES-CBC) / AuthEnvelopedData (AES-GCM) carrying an RFC 9629 ML-KEM
// KEMRecipientInfo. BouncyCastle 2.6.x has no managed builder for KEM recipients, so the CMS is
// assembled by hand. SCEP uses the CBC path (EnvelopedData); GCM is ported for completeness.
internal static class BcKemEnvelope {
    private static readonly DerObjectIdentifier IdOriKem = new DerObjectIdentifier("1.2.840.113549.1.9.16.13.3");
    private static readonly DerObjectIdentifier IdAes256Gcm = NistObjectIdentifiers.IdAes256Gcm;
    // id-ct-authEnvelopedData { 1.2.840.113549.1.9.16.1.23 }
    private static readonly DerObjectIdentifier IdCtAuthEnvelopedData = new DerObjectIdentifier("1.2.840.113549.1.9.16.1.23");
    private const string OidAes128Cbc = "2.16.840.1.101.3.4.1.2";
    private const string OidAes256Cbc = "2.16.840.1.101.3.4.1.42";
    private const int GcmTagLenBytes = 16;

    // -------------------------------------------------------------------------
    // CBC — EnvelopedData (RFC 5652). content_cipher_oid is honored (AES-128/256-CBC).
    // -------------------------------------------------------------------------

    public static byte[] EncryptCbc(byte[] plaintext, MLKemPublicKeyParameters recipient_public, byte[] recipient_key_id, string content_cipher_oid) {
        SecureRandom random;
        byte[] cek;
        byte[] iv;
        byte[] encrypted_content;
        AlgorithmIdentifier content_enc_alg;
        EncryptedContentInfo eci;
        RecipientInfo recipient_info;
        EnvelopedData enveloped_data;

        random = new SecureRandom();
        cek = new byte[CekLength(content_cipher_oid)];
        random.NextBytes(cek);
        iv = new byte[16];
        random.NextBytes(iv);

        encrypted_content = AesCbc(true, cek, iv, plaintext);
        content_enc_alg = new AlgorithmIdentifier(new DerObjectIdentifier(content_cipher_oid), new DerOctetString(iv));
        eci = new EncryptedContentInfo(CmsObjectIdentifiers.Data, content_enc_alg, new DerOctetString(encrypted_content));

        recipient_info = BcKemRecipientInfo.CreateRecipientInfo(cek, recipient_public, recipient_key_id, null);
        Array.Clear(cek, 0, cek.Length);

        enveloped_data = new EnvelopedData(null, new DerSet(recipient_info), eci, (Asn1Set)null!);
        return new ContentInfo(CmsObjectIdentifiers.EnvelopedData, enveloped_data).GetDerEncoded();
    }

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
        cek = BcKemRecipientInfo.RecoverCek(kem_ri, recipient_private);

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

    // -------------------------------------------------------------------------
    // GCM — AuthEnvelopedData (RFC 5083/5084), AES-256-GCM. Ported for completeness; not used by SCEP.
    // -------------------------------------------------------------------------

    public static byte[] EncryptGcm(byte[] plaintext, MLKemPublicKeyParameters recipient_public, byte[] recipient_key_id) {
        SecureRandom random;
        byte[] cek;
        byte[] nonce;
        byte[] cipher_with_tag;
        byte[] ciphertext;
        byte[] tag;
        Asn1EncodableVector gcm_params;
        AlgorithmIdentifier content_enc_alg;
        EncryptedContentInfo eci;
        RecipientInfo recipient_info;
        Asn1EncodableVector v;

        random = new SecureRandom();
        cek = new byte[32];
        random.NextBytes(cek);
        nonce = new byte[12];
        random.NextBytes(nonce);

        cipher_with_tag = AesGcm(true, cek, nonce, plaintext, GcmTagLenBytes);
        ciphertext = new byte[cipher_with_tag.Length - GcmTagLenBytes];
        tag = new byte[GcmTagLenBytes];
        Array.Copy(cipher_with_tag, 0, ciphertext, 0, ciphertext.Length);
        Array.Copy(cipher_with_tag, ciphertext.Length, tag, 0, GcmTagLenBytes);

        gcm_params = new Asn1EncodableVector();
        gcm_params.Add(new DerOctetString(nonce));
        gcm_params.Add(new DerInteger(GcmTagLenBytes));
        content_enc_alg = new AlgorithmIdentifier(IdAes256Gcm, new DerSequence(gcm_params));
        eci = new EncryptedContentInfo(CmsObjectIdentifiers.Data, content_enc_alg, new DerOctetString(ciphertext));

        recipient_info = BcKemRecipientInfo.CreateRecipientInfo(cek, recipient_public, recipient_key_id, null);
        Array.Clear(cek, 0, cek.Length);

        v = new Asn1EncodableVector();
        v.Add(new DerInteger(0));                  // version (RFC 5083)
        v.Add(new DerSet(recipient_info));         // recipientInfos
        v.Add(eci);                                // authEncryptedContentInfo
        v.Add(new DerOctetString(tag));            // mac (GCM tag)
        return new ContentInfo(IdCtAuthEnvelopedData, new DerSequence(v)).GetDerEncoded();
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
        cek = BcKemRecipientInfo.RecoverCek(kem_ri, recipient_private);

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

    // -------------------------------------------------------------------------
    // helpers
    // -------------------------------------------------------------------------

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

    private static int CekLength(string content_cipher_oid) {
        if (content_cipher_oid == OidAes256Cbc) { return 32; }
        if (content_cipher_oid == OidAes128Cbc) { return 16; }
        return 16;   // default to AES-128
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
}
