namespace DevToys.CryptoTools.Cryptography;

internal static class DraftTransfer
{
    internal const string KeyPairDataType = "DevToys.CryptoTools.KeyPair";
    internal const string CsrDataType = "DevToys.CryptoTools.Csr";
}

internal sealed record KeyPairDraft(string Algorithm, string PublicKey, string PrivateKey);
internal sealed record CsrDraft(string RequestPem, string PrivateKey = "");
