using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DevToys.CryptoTools.Cryptography;

internal static class EllipticCurveKeyImport
{
    internal static readonly string[] CoordinateAlgorithms = [.. EcDomains.Curves.Select(curve => "ECDSA-" + curve), "SM2"];

    internal static string Import(byte[] data)
    {
        try
        {
            ArgumentNullException.ThrowIfNull(data);
            if (data.Length == 0) throw new ArgumentException();
            string text = Encoding.UTF8.GetString(data).TrimStart('\uFEFF', ' ', '\t', '\r', '\n');
            object? parsed;
            if (text.StartsWith("-----BEGIN ", StringComparison.Ordinal))
            {
                using var reader = new StringReader(text);
                parsed = new PemReader(reader).ReadObject();
            }
            else
            {
                var sequence = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(data));
                parsed = sequence.Count switch
                {
                    2 when sequence[0] is Asn1Sequence => PublicKeyFactory.CreateKey(data),
                    >= 3 when sequence[0] is DerInteger && sequence[1] is Asn1Sequence => PrivateKeyFactory.CreateKey(data),
                    3 when sequence[0] is Asn1Sequence => new X509CertificateParser().ReadCertificate(data),
                    >= 2 when sequence[0] is DerInteger && sequence[1] is Asn1OctetString => ReadSec1(data),
                    _ => throw new ArgumentException()
                };
            }

            AsymmetricKeyParameter key = parsed switch
            {
                X509Certificate certificate => certificate.GetPublicKey(),
                AsymmetricCipherKeyPair pair => pair.Private,
                AsymmetricKeyParameter parameter => parameter,
                _ => throw new ArgumentException()
            };
            if (!key.IsPrivate)
                return PemEncoding.WriteString("PUBLIC KEY", SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key).GetDerEncoded());
            byte[] privateDer = PrivateKeyInfoFactory.CreatePrivateKeyInfo(key).GetDerEncoded();
            try { return PemEncoding.WriteString("PRIVATE KEY", privateDer); }
            finally { CryptographicOperations.ZeroMemory(privateDer); }
        }
        catch (Exception ex) when (ex is ArgumentException or IOException or GeneralSecurityException or InvalidOperationException or InvalidCastException or IndexOutOfRangeException or CryptoException)
        {
            throw new ArgumentException(L("InvalidKeyFile"), ex);
        }
    }

    internal static string FromCoordinates(string algorithm, string xHex, string yHex)
    {
        try
        {
            if (!CoordinateAlgorithms.Contains(algorithm)) throw new ArgumentException();
            var parameters = EcDomains.ForAlgorithm(algorithm);
            int width = (parameters.Curve.FieldSize + 7) / 8;
            var x = Coordinate(xHex, width);
            var y = Coordinate(yHex, width);
            var point = parameters.Curve.ValidatePoint(x, y);
            if (point.IsInfinity || !point.Multiply(parameters.N).IsInfinity) throw new ArgumentException();
            var key = new ECPublicKeyParameters(point, parameters);
            return PemEncoding.WriteString("PUBLIC KEY", SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key).GetDerEncoded());
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException or ArithmeticException or InvalidOperationException)
        {
            throw new ArgumentException(L("InvalidCoordinates"), ex);
        }
    }

    private static object? ReadSec1(byte[] data)
    {
        using var reader = new StringReader(PemEncoding.WriteString("EC PRIVATE KEY", data));
        return new PemReader(reader).ReadObject();
    }

    private static BigInteger Coordinate(string text, int width)
    {
        string hex = string.Concat(text.Where(c => !char.IsWhiteSpace(c)));
        if (hex.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) hex = hex[2..];
        if (hex.Length == 0 || hex.Length > width * 2) throw new ArgumentException();
        if (hex.Length % 2 != 0) hex = "0" + hex;
        return new BigInteger(1, Convert.FromHexString(hex));
    }
}
