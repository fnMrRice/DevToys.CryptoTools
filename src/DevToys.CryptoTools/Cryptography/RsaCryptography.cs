using System.Security.Cryptography;
using System.Text;

namespace DevToys.CryptoTools.Cryptography;

internal static class RsaCryptography
{
    internal static readonly string[] EncryptionPaddings = ["OAEP-SHA256", "OAEP-SHA384", "OAEP-SHA512", "PKCS1"];
    internal static readonly string[] Hashes = ["SHA256", "SHA384", "SHA512"];
    internal static readonly string[] SignaturePaddings = ["PSS", "PKCS1"];

    internal static string Encrypt(string pem, string text, string padding)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        var bytes = Encoding.UTF8.GetBytes(text);
        int overhead = padding switch { "OAEP-SHA256" => 66, "OAEP-SHA384" => 98, "OAEP-SHA512" => 130, "PKCS1" => 11, _ => throw new ArgumentException(L("InvalidAlgorithm")) };
        if (bytes.Length > rsa.KeySize / 8 - overhead) throw new ArgumentException(L("MessageTooLong"));
        return Convert.ToBase64String(rsa.Encrypt(bytes, EncryptionPadding(padding)));
    }

    internal static string Decrypt(string pem, string text, string padding)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return new UTF8Encoding(false, true).GetString(rsa.Decrypt(Convert.FromBase64String(text), EncryptionPadding(padding)));
    }

    internal static string Sign(string pem, string text, string hash, string padding)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return Convert.ToBase64String(rsa.SignData(Encoding.UTF8.GetBytes(text), Hash(hash), SignaturePadding(padding)));
    }

    internal static bool Verify(string pem, string text, string signature, string hash, string padding)
    {
        using var rsa = RSA.Create();
        rsa.ImportFromPem(pem);
        return rsa.VerifyData(Encoding.UTF8.GetBytes(text), Convert.FromBase64String(signature), Hash(hash), SignaturePadding(padding));
    }

    private static RSAEncryptionPadding EncryptionPadding(string name) => name switch
    {
        "OAEP-SHA256" => RSAEncryptionPadding.OaepSHA256,
        "OAEP-SHA384" => RSAEncryptionPadding.OaepSHA384,
        "OAEP-SHA512" => RSAEncryptionPadding.OaepSHA512,
        "PKCS1" => RSAEncryptionPadding.Pkcs1,
        _ => throw new ArgumentException(L("InvalidAlgorithm"))
    };

    private static RSASignaturePadding SignaturePadding(string name) => name switch
    {
        "PSS" => RSASignaturePadding.Pss,
        "PKCS1" => RSASignaturePadding.Pkcs1,
        _ => throw new ArgumentException(L("InvalidAlgorithm"))
    };

    private static HashAlgorithmName Hash(string name) => Hashes.Contains(name) ? new(name) : throw new ArgumentException(L("InvalidAlgorithm"));
}
