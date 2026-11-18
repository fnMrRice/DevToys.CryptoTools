using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace DevToys.CryptoTools.Cryptography;

internal static class RsaPublicKeyInput
{
    internal static string Decode(string text, PublicKeyEncoding encoding)
    {
        try
        {
            byte[] bytes = DecodeBytes(text, encoding);
            try
            {
                string imported = EllipticCurveKeyImport.Import(bytes);
                if (KeyGenerator.ReadKey(imported, false) is not RsaKeyParameters { IsPrivate: false })
                    throw new ArgumentException();
                using var rsa = RSA.Create();
                rsa.ImportFromPem(imported);
                return rsa.ExportSubjectPublicKeyInfoPem();
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or CryptographicException or IOException or InvalidOperationException)
        {
            throw new ArgumentException(L("InvalidKey"), ex);
        }
    }

    internal static string FromParameters(string modulus, string exponent, PublicKeyEncoding encoding)
    {
        try
        {
            if (encoding is not (PublicKeyEncoding.Base64 or PublicKeyEncoding.Hex)) throw new ArgumentException(L("InvalidEncoding"));
            byte[] nBytes = DecodeBytes(modulus, encoding);
            byte[] eBytes = DecodeBytes(exponent, encoding);
            var n = new BigInteger(1, nBytes);
            var e = new BigInteger(1, eBytes);
            if (n.BitLength < 512 || !n.TestBit(0) || e.CompareTo(BigInteger.Three) < 0 || !e.TestBit(0) || e.CompareTo(n) >= 0)
                throw new ArgumentException();
            using var rsa = RSA.Create();
            rsa.ImportParameters(new RSAParameters { Modulus = n.ToByteArrayUnsigned(), Exponent = e.ToByteArrayUnsigned() });
            return rsa.ExportSubjectPublicKeyInfoPem();
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or CryptographicException or ArithmeticException or InvalidOperationException)
        {
            throw new ArgumentException(L("InvalidKey"), ex);
        }
    }

    private static byte[] DecodeBytes(string text, PublicKeyEncoding encoding) => encoding switch
    {
        PublicKeyEncoding.Pem => Encoding.UTF8.GetBytes(text),
        PublicKeyEncoding.Base64 => Convert.FromBase64String(text),
        PublicKeyEncoding.Hex => HexBytes(text),
        _ => throw new ArgumentException(L("InvalidEncoding"))
    };

    private static byte[] HexBytes(string text)
    {
        string hex = string.Concat(text.Where(c => !char.IsWhiteSpace(c)));
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex[2..];
        if (hex.Length % 2 != 0) hex = "0" + hex;
        return Convert.FromHexString(hex);
    }
}
