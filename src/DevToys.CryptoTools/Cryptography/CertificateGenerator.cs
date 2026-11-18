using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DevToys.CryptoTools.Cryptography;

internal sealed record CertificateMaterial(string Document, string PrivateKey);

internal static class CertificateGenerator
{
    internal static readonly string[] Algorithms = ["RSA-2048", "RSA-3072", "RSA-4096", "ECDSA-P256", "ECDSA-P384", "ECDSA-P521", "SM2", "Ed25519", "Ed448"];

    internal static CertificateMaterial Generate(string algorithm, string subject, string dnsNames, int days, bool csr)
    {
        if (!Algorithms.Contains(algorithm)) throw new ArgumentException(L("InvalidAlgorithm"));
        if (days is < 1 or > 3650) throw new ArgumentException(L("InvalidValidity"));
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        var name = new X509Name(subject);
        var keys = KeyGenerator.Generate(algorithm);
        var publicKey = KeyGenerator.ReadKey(keys.PublicKey, false);
        var privateKey = KeyGenerator.ReadKey(keys.PrivateKey, true);
        string signatureAlgorithm = algorithm switch
        {
            "SM2" => "SM3withSM2",
            "Ed25519" => "Ed25519",
            "Ed448" => "Ed448",
            "ECDSA-P384" => "SHA384withECDSA",
            "ECDSA-P521" => "SHA512withECDSA",
            "ECDSA-P256" => "SHA256withECDSA",
            _ => "SHA256withRSA"
        };
        var signer = new Asn1SignatureFactory(signatureAlgorithm, privateKey, new SecureRandom());
        var extensions = new X509ExtensionsGenerator();
        extensions.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
        extensions.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(
            KeyUsage.DigitalSignature | (algorithm.StartsWith("RSA-", StringComparison.Ordinal) ? KeyUsage.KeyEncipherment : 0)));
        string[] names = dnsNames.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (names.Length > 0)
        {
            var idn = new System.Globalization.IdnMapping();
            var generalNames = names.Select(dns => new GeneralName(GeneralName.DnsName, idn.GetAscii(dns))).ToArray();
            extensions.AddExtension(X509Extensions.SubjectAlternativeName, false, new GeneralNames(generalNames));
        }
        if (csr)
        {
            var attribute = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions.Generate()));
            var request = new Pkcs10CertificationRequest(signer, name, publicKey, new DerSet(attribute));
            return new(PemEncoding.WriteString("CERTIFICATE REQUEST", request.GetDerEncoded()), keys.PrivateKey);
        }
        var generator = new X509V3CertificateGenerator();
        byte[] serial = RandomNumberGenerator.GetBytes(20);
        serial[0] &= 0x7f;
        serial[^1] |= 1;
        generator.SetSerialNumber(new BigInteger(1, serial));
        generator.SetIssuerDN(name);
        generator.SetSubjectDN(name);
        var now = DateTime.UtcNow;
        generator.SetNotBefore(now.AddMinutes(-5));
        generator.SetNotAfter(now.AddDays(days));
        generator.SetPublicKey(publicKey);
        generator.AddExtensions(extensions.Generate());
        var certificate = generator.Generate(signer);
        return new(PemEncoding.WriteString("CERTIFICATE", certificate.GetEncoded()), keys.PrivateKey);
    }
}
