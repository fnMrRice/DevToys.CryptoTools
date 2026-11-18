using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;

namespace DevToys.CryptoTools.Cryptography;

internal enum KeyOutputFormat { Pem, Pkcs8Pem, TraditionalPem, DerHex, DerBase64 }

internal static class KeyOutputFormatter
{
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static string FormatPrivate(string canonicalPkcs8Pem, KeyOutputFormat format) => Format(canonicalPkcs8Pem, format, true);
    internal static string FormatPublic(string canonicalSpkiPem, KeyOutputFormat format) => Format(canonicalSpkiPem, format, false);
    internal static bool CanUseTraditionalPrivatePem(string canonicalPkcs8Pem) => CanUseTraditional(canonicalPkcs8Pem, true);
    internal static bool CanUseTraditionalPublicPem(string canonicalSpkiPem) => CanUseTraditional(canonicalSpkiPem, false);
    internal static byte[] ExportPrivate(string canonicalPem, KeyOutputFormat format) => Export(canonicalPem, format, true);
    internal static byte[] ExportPublic(string canonicalPem, KeyOutputFormat format) => Export(canonicalPem, format, false);

    private static string Format(string canonicalPem, KeyOutputFormat format, bool privateKey)
    {
        byte[] der = ReadCanonicalDer(canonicalPem, privateKey, out bool encrypted);
        try
        {
            switch (format)
            {
                case KeyOutputFormat.Pem:
                case KeyOutputFormat.Pkcs8Pem when privateKey:
                    return canonicalPem;
                case KeyOutputFormat.DerHex:
                    return Convert.ToHexString(der);
                case KeyOutputFormat.DerBase64:
                    return Convert.ToBase64String(der);
                case KeyOutputFormat.TraditionalPem:
                    byte[] traditional = TraditionalDer(der, privateKey, encrypted, out string label);
                    try { return PemEncoding.WriteString(label, traditional); }
                    finally { if (privateKey) CryptographicOperations.ZeroMemory(traditional); }
                default:
                    throw Unavailable();
            }
        }
        finally { if (privateKey) CryptographicOperations.ZeroMemory(der); }
    }

    private static byte[] Export(string canonicalPem, KeyOutputFormat format, bool privateKey)
    {
        // Hex/Base64 are editor representations. Export the original DER container,
        // including its encryption and algorithm parameters, rather than that text.
        if (format is KeyOutputFormat.DerHex or KeyOutputFormat.DerBase64)
            return ReadCanonicalDer(canonicalPem, privateKey, out _);
        return Utf8.GetBytes(Format(canonicalPem, format, privateKey));
    }

    private static bool CanUseTraditional(string canonicalPem, bool privateKey)
    {
        byte[] der = [];
        byte[] traditional = [];
        try
        {
            der = ReadCanonicalDer(canonicalPem, privateKey, out bool encrypted);
            traditional = TraditionalDer(der, privateKey, encrypted, out _);
            return true;
        }
        catch (ArgumentException) { return false; }
        finally
        {
            if (privateKey)
            {
                CryptographicOperations.ZeroMemory(der);
                CryptographicOperations.ZeroMemory(traditional);
            }
        }
    }

    private static byte[] ReadCanonicalDer(string pem, bool privateKey, out bool encrypted)
    {
        encrypted = false;
        if (string.IsNullOrWhiteSpace(pem) || !PemEncoding.TryFind(pem, out PemFields fields))
            throw Unavailable();
        string label = pem[fields.Label];
        encrypted = privateKey && label == "ENCRYPTED PRIVATE KEY";
        if (privateKey ? label != "PRIVATE KEY" && !encrypted : label != "PUBLIC KEY")
            throw Unavailable();

        byte[] der = Convert.FromBase64String(pem[fields.Base64Data]);
        try
        {
            if (!privateKey)
                _ = SubjectPublicKeyInfo.GetInstance(der);
            else if (encrypted)
                _ = EncryptedPrivateKeyInfo.GetInstance(der);
            else
                _ = PrivateKeyInfo.GetInstance(der);
            return der;
        }
        catch (Exception error) when (error is ArgumentException or IOException or InvalidOperationException)
        {
            if (privateKey) CryptographicOperations.ZeroMemory(der);
            throw Unavailable(error);
        }
    }

    private static byte[] TraditionalDer(byte[] der, bool privateKey, bool encrypted, out string label)
    {
        if (encrypted) throw Unavailable();
        try
        {
            if (!privateKey)
            {
                var publicInfo = SubjectPublicKeyInfo.GetInstance(der);
                if (!publicInfo.Algorithm.Algorithm.Equals(PkcsObjectIdentifiers.RsaEncryption))
                    throw Unavailable();
                label = "RSA PUBLIC KEY";
                return RsaPublicKeyStructure.GetInstance(publicInfo.ParsePublicKey()).GetDerEncoded();
            }

            var privateInfo = PrivateKeyInfo.GetInstance(der);
            var algorithm = privateInfo.PrivateKeyAlgorithm;
            if (algorithm.Algorithm.Equals(PkcsObjectIdentifiers.RsaEncryption))
            {
                label = "RSA PRIVATE KEY";
                return RsaPrivateKeyStructure.GetInstance(privateInfo.ParsePrivateKey()).GetDerEncoded();
            }
            if (algorithm.Algorithm.Equals(X9ObjectIdentifiers.IdECPublicKey))
            {
                var ec = ECPrivateKeyStructure.GetInstance(privateInfo.ParsePrivateKey());
                Asn1Encodable parameters = algorithm.Parameters ?? ec.Parameters;
                if (parameters is null or DerNull)
                    throw Unavailable();
                label = "EC PRIVATE KEY";
                // SEC1 needs its curve parameters after leaving the PKCS#8 wrapper.
                return new ECPrivateKeyStructure(ec.PrivateKey, parameters, ec.PublicKey ?? privateInfo.PublicKey).GetDerEncoded();
            }
            throw Unavailable();
        }
        catch (Exception error) when (error is ArgumentException or IOException or InvalidOperationException)
        {
            throw Unavailable(error);
        }
    }

    private static ArgumentException Unavailable(Exception? inner = null) => new(L("KeyOutputFormatUnavailable"), inner);
}
