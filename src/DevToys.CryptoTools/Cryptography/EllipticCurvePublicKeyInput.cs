using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

namespace DevToys.CryptoTools.Cryptography;

internal enum PublicKeyEncoding { Pem, Base64, Hex }

internal static class EllipticCurvePublicKeyInput
{
    internal static string Decode(string algorithm, string text, PublicKeyEncoding encoding)
    {
        try
        {
            byte[] bytes = encoding switch
            {
                PublicKeyEncoding.Pem => Encoding.UTF8.GetBytes(text),
                PublicKeyEncoding.Base64 => Convert.FromBase64String(text),
                PublicKeyEncoding.Hex => HexBytes(text),
                _ => throw new ArgumentException(L("InvalidEncoding"))
            };
            try
            {
                string? imported = null;
                try { imported = EllipticCurveKeyImport.Import(bytes); }
                catch (ArgumentException) when (encoding != PublicKeyEncoding.Pem) { }
                // Successfully imported private key material must never fall through
                // to a raw public-key interpretation.
                AsymmetricKeyParameter key = imported is null
                    ? ReadRaw(algorithm, bytes)
                    : KeyGenerator.ReadKey(imported, false);
                ValidatePublicKey(algorithm, key);
                return PemEncoding.WriteString("PUBLIC KEY", SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key).GetDerEncoded());
            }
            finally { CryptographicOperations.ZeroMemory(bytes); }
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or ArithmeticException or InvalidOperationException or IOException)
        {
            throw new ArgumentException(L("InvalidKey"), ex);
        }
    }

    internal static string FromCoordinates(string algorithm, string x, string y, PublicKeyEncoding encoding)
    {
        try
        {
            if (encoding is not (PublicKeyEncoding.Hex or PublicKeyEncoding.Base64)) throw new ArgumentException(L("InvalidEncoding"));
            string normalizedAlgorithm = algorithm.StartsWith("ECDH-", StringComparison.Ordinal)
                ? "ECDSA-" + algorithm[5..]
                : algorithm.StartsWith("SM2-", StringComparison.Ordinal) ? "SM2" : algorithm;
            string xHex = encoding == PublicKeyEncoding.Hex ? x : Convert.ToHexString(Convert.FromBase64String(x));
            string yHex = encoding == PublicKeyEncoding.Hex ? y : Convert.ToHexString(Convert.FromBase64String(y));
            string pem = EllipticCurveKeyImport.FromCoordinates(normalizedAlgorithm, xHex, yHex);
            ValidatePublicKey(algorithm, KeyGenerator.ReadKey(pem, false));
            return pem;
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or ArithmeticException or InvalidOperationException)
        {
            throw new ArgumentException(L("InvalidCoordinates"), ex);
        }
    }

    private static AsymmetricKeyParameter ReadRaw(string algorithm, byte[] bytes)
    {
        if (EcDomains.SupportsCoordinates(algorithm))
        {
            var domain = EcDomains.ForAlgorithm(algorithm);
            int width = (domain.Curve.FieldSize + 7) / 8;
            byte[] encoded = bytes.Length == width * 2 ? [4, .. bytes] : bytes;
            bool uncompressed = encoded.Length == 1 + width * 2 && encoded[0] == 4;
            bool compressed = encoded.Length == 1 + width && encoded[0] is 2 or 3;
            if (!uncompressed && !compressed) throw new ArgumentException();
            var point = domain.Curve.DecodePoint(encoded).Normalize();
            if (point.IsInfinity || !point.IsValid() || !point.Multiply(domain.N).IsInfinity) throw new ArgumentException();
            return new ECPublicKeyParameters(point, domain);
        }
        return algorithm switch
        {
            "Ed25519" when bytes.Length == 32 => new Ed25519PublicKeyParameters(bytes, 0),
            "Ed448" when bytes.Length == 57 => new Ed448PublicKeyParameters(bytes, 0),
            "X25519" when bytes.Length == 32 => new X25519PublicKeyParameters(bytes, 0),
            "X448" when bytes.Length == 56 => new X448PublicKeyParameters(bytes, 0),
            _ => throw new ArgumentException()
        };
    }

    private static void ValidatePublicKey(string algorithm, AsymmetricKeyParameter key)
    {
        bool valid = !key.IsPrivate && algorithm switch
        {
            "Ed25519" => key is Ed25519PublicKeyParameters,
            "Ed448" => key is Ed448PublicKeyParameters,
            "X25519" => key is X25519PublicKeyParameters,
            "X448" => key is X448PublicKeyParameters,
            _ => key is ECPublicKeyParameters ec && EcDomains.SupportsCoordinates(algorithm)
                && ec.Parameters.Equals(EcDomains.ForAlgorithm(algorithm))
                && !ec.Q.IsInfinity && ec.Q.IsValid() && ec.Q.Multiply(ec.Parameters.N).IsInfinity
        };
        if (!valid) throw new ArgumentException(L("InvalidKey"));
    }

    private static byte[] HexBytes(string text)
    {
        string hex = string.Concat(text.Where(c => !char.IsWhiteSpace(c)));
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex[2..];
        return Convert.FromHexString(hex);
    }
}
