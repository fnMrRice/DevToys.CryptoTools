using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;

namespace DevToys.CryptoTools.Cryptography;

internal sealed record CertificateMaterial(string Document, string PrivateKey);

internal static class CertificateGenerator
{
    internal static readonly string[] Algorithms = KeyGenerator.Algorithms.Where(algorithm =>
        algorithm.StartsWith("RSA-", StringComparison.Ordinal) || algorithm.StartsWith("ECDSA-", StringComparison.Ordinal)
        || algorithm is "SM2" or "Ed25519" or "Ed448").ToArray();

    internal static CertificateMaterial Generate(string algorithm, string subject, string dnsNames, int days, bool csr)
    {
        if (!Algorithms.Contains(algorithm)) throw new ArgumentException(L("InvalidAlgorithm"));
        if (days is < 1 or > 3650) throw new ArgumentException(L("InvalidValidity"));
        var options = new CertificateOptions
        {
            Algorithm = algorithm, Subject = subject,
            DnsNames = dnsNames.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries),
            NotBeforeUtc = DateTime.UtcNow.AddMinutes(-5), NotAfterUtc = DateTime.UtcNow.AddDays(days),
            KeyUsage = KeyUsage.DigitalSignature | (algorithm.StartsWith("RSA-", StringComparison.Ordinal) ? KeyUsage.KeyEncipherment : 0)
        };
        return csr ? CertificateRequestService.Generate(options) : Generate(options);
    }

    internal static CertificateMaterial Generate(CertificateOptions options)
    {
        DateTime notBefore = Utc(options.NotBeforeUtc);
        DateTime notAfter = Utc(options.NotAfterUtc);
        if (notAfter <= notBefore) throw new ArgumentException(L("InvalidValidity"));
        AsymmetricKeyParameter publicKey;
        string privatePem;
        string subject = options.Subject;
        if (string.IsNullOrWhiteSpace(options.CsrPem))
        {
            if (string.IsNullOrWhiteSpace(options.PrivateKeyPem) && !string.IsNullOrWhiteSpace(options.PublicKeyPem))
            {
                publicKey = KeyGenerator.ReadKey(options.PublicKeyPem, false);
                privatePem = "";
            }
            else
            {
                var keys = CertificateRequestService.GetKeyMaterial(options, requireSigning: false);
                publicKey = keys.Public;
                privatePem = keys.PrivatePem;
            }
        }
        else
        {
            var request = CertificateRequestService.Parse(System.Text.Encoding.UTF8.GetBytes(options.CsrPem));
            publicKey = request.GetPublicKey();
            if (!string.IsNullOrWhiteSpace(options.PublicKeyPem)
                && !CertificateRequestService.PublicKeysEqual(publicKey, KeyGenerator.ReadKey(options.PublicKeyPem, false)))
                throw new ArgumentException(L("KeyPairMismatch"));
            if (string.IsNullOrWhiteSpace(subject)) subject = request.GetCertificationRequestInfo().Subject.ToString();
            privatePem = options.PrivateKeyPem;
            if (!string.IsNullOrWhiteSpace(privatePem))
            {
                var ownKey = CertificateRequestService.GetKeyMaterial(options, requireSigning: false);
                if (!CertificateRequestService.PublicKeysEqual(ownKey.Public, publicKey)) throw new ArgumentException(L("KeyPairMismatch"));
            }
        }
        ArgumentException.ThrowIfNullOrWhiteSpace(subject);
        var subjectName = new X509Name(subject);
        AsymmetricKeyParameter signerPrivate;
        AsymmetricKeyParameter signerPublic;
        X509Name issuerName;
        if (!string.IsNullOrWhiteSpace(options.IssuerCertificatePem) || !string.IsNullOrWhiteSpace(options.IssuerPrivateKeyPem))
        {
            if (string.IsNullOrWhiteSpace(options.IssuerCertificatePem) || string.IsNullOrWhiteSpace(options.IssuerPrivateKeyPem))
                throw new ArgumentException(L("InvalidIssuer"));
            var issuer = ReadCertificate(System.Text.Encoding.UTF8.GetBytes(options.IssuerCertificatePem));
            signerPrivate = KeyGenerator.ReadKey(options.IssuerPrivateKeyPem, true);
            signerPublic = issuer.GetPublicKey();
            bool[]? usage = issuer.GetKeyUsage();
            int pathLimit = issuer.GetBasicConstraints();
            if (pathLimit < 0 || (usage is not null && (usage.Length <= 5 || !usage[5]))
                || !CertificateRequestService.PublicKeysEqual(CertificateRequestService.PublicFromPrivate(signerPrivate), signerPublic)
                || notBefore < issuer.NotBefore || notAfter > issuer.NotAfter
                || (options.IsCa && pathLimit != int.MaxValue && (pathLimit == 0 || !options.PathLength.HasValue || options.PathLength.Value >= pathLimit)))
                throw new ArgumentException(L("InvalidIssuer"));
            issuerName = issuer.SubjectDN;
        }
        else
        {
            if (string.IsNullOrWhiteSpace(privatePem)) throw new ArgumentException(L("InvalidIssuer"));
            signerPrivate = KeyGenerator.ReadKey(privatePem, true);
            signerPublic = CertificateRequestService.PublicFromPrivate(signerPrivate);
            if (!CertificateRequestService.PublicKeysEqual(signerPublic, publicKey)) throw new ArgumentException(L("KeyPairMismatch"));
            issuerName = subjectName;
        }
        if (!string.IsNullOrWhiteSpace(options.Issuer) && !new X509Name(options.Issuer).Equivalent(issuerName))
            throw new ArgumentException(L("InvalidIssuer"));

        var generator = new X509V3CertificateGenerator();
        generator.SetSerialNumber(Serial(options.SerialHex));
        generator.SetIssuerDN(issuerName);
        generator.SetSubjectDN(subjectName);
        generator.SetNotBefore(notBefore);
        generator.SetNotAfter(notAfter);
        generator.SetPublicKey(publicKey);
        generator.AddExtensions(CertificateRequestService.BuildExtensions(options));
        var subjectInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
        var issuerInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(signerPublic);
        generator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, X509ExtensionUtilities.CreateSubjectKeyIdentifier(subjectInfo));
        generator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, X509ExtensionUtilities.CreateAuthorityKeyIdentifier(issuerInfo));
        var certificate = generator.Generate(CertificateRequestService.SignatureFactory(signerPrivate, options));
        certificate.Verify(signerPublic);
        return new(PemEncoding.WriteString("CERTIFICATE", certificate.GetEncoded()), privatePem);
    }

    internal static X509Certificate ReadCertificate(byte[] data)
    {
        try { return new X509CertificateParser().ReadCertificate(CertificateRequestService.DecodePemOrDer(data, "CERTIFICATE")) ?? throw new ArgumentException(); }
        catch (Exception ex) when (ex is not OutOfMemoryException) { throw new ArgumentException(L("InvalidIssuer"), ex); }
    }

    private static DateTime Utc(DateTime value) => value.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(value, DateTimeKind.Utc) : value.ToUniversalTime();

    private static BigInteger Serial(string hex)
    {
        if (string.IsNullOrWhiteSpace(hex))
        {
            byte[] bytes = RandomNumberGenerator.GetBytes(20);
            bytes[0] &= 0x7f;
            bytes[^1] |= 1;
            return new BigInteger(1, bytes);
        }
        try
        {
            string normalized = string.Concat(hex.Where(c => !char.IsWhiteSpace(c)));
            if (normalized.StartsWith("0x", StringComparison.OrdinalIgnoreCase)) normalized = normalized[2..];
            if (normalized.Length % 2 != 0) normalized = "0" + normalized;
            byte[] bytes = Convert.FromHexString(normalized);
            var serial = new BigInteger(1, bytes);
            if (serial.SignValue <= 0 || serial.BitLength > 159) throw new ArgumentException();
            return serial;
        }
        catch (Exception ex) when (ex is ArgumentException or FormatException) { throw new ArgumentException(L("InvalidSerial"), ex); }
    }
}
