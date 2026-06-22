namespace ScepWright.Crypto.BouncyCastle;

internal static class ScepAttributes {
    public const string MessageType = "2.16.840.1.113733.1.9.2";
    public const string PkiStatus = "2.16.840.1.113733.1.9.3";
    public const string FailInfo = "2.16.840.1.113733.1.9.4";
    public const string SenderNonce = "2.16.840.1.113733.1.9.5";
    public const string RecipientNonce = "2.16.840.1.113733.1.9.6";
    public const string TransId = "2.16.840.1.113733.1.9.7";

    public static string NumberFor(ScepWright.Crypto.MessageType type) {
        switch (type) {
            case ScepWright.Crypto.MessageType.CertRep: return "3";
            case ScepWright.Crypto.MessageType.RenewalReq: return "17";
            case ScepWright.Crypto.MessageType.PkcsReq: return "19";
            case ScepWright.Crypto.MessageType.CertPoll: return "20";
            case ScepWright.Crypto.MessageType.GetCert: return "21";
            case ScepWright.Crypto.MessageType.GetCrl: return "22";
            default: return ((int)type).ToString();
        }
    }
}
