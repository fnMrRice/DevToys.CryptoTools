using Org.BouncyCastle.Asn1.X509;

namespace DevToys.CryptoTools.Cryptography;

internal sealed record CustomCertificateExtension(string Oid, bool Critical, string DerBase64);

internal sealed record CertificateOptions
{
    public string Algorithm { get; init; } = "RSA-2048";
    public string Subject { get; init; } = "CN=localhost";
    public string? Issuer { get; init; }
    public string HashAlgorithm { get; init; } = "Auto";
    public bool RsaPss { get; init; }
    public DateTime NotBeforeUtc { get; init; } = DateTime.UtcNow.AddMinutes(-5);
    public DateTime NotAfterUtc { get; init; } = DateTime.UtcNow.AddDays(365);
    public string SerialHex { get; init; } = "";
    public bool IsCa { get; init; }
    public int? PathLength { get; init; }
    public int KeyUsage { get; init; } = Org.BouncyCastle.Asn1.X509.KeyUsage.DigitalSignature;
    public bool KeyUsageCritical { get; init; } = true;
    public bool BasicConstraintsCritical { get; init; } = true;
    public string[] EnhancedKeyUsageOids { get; init; } = [];
    public bool EnhancedKeyUsageCritical { get; init; }
    public string[] DnsNames { get; init; } = [];
    public string[] IpAddresses { get; init; } = [];
    public string[] EmailAddresses { get; init; } = [];
    public string[] Uris { get; init; } = [];
    public bool SanCritical { get; init; }
    public CustomCertificateExtension[] CustomExtensions { get; init; } = [];
    public string PrivateKeyPem { get; init; } = "";
    public string PublicKeyPem { get; init; } = "";
    public string IssuerPrivateKeyPem { get; init; } = "";
    public string IssuerCertificatePem { get; init; } = "";
    public string CsrPem { get; init; } = "";
}

internal sealed record CertificateRequestDetails(
    string Subject, string PublicKeyPem, string[] DnsNames, string[] IpAddresses, string[] EmailAddresses, string[] Uris,
    CertificateOptions? RequestedOptions = null);
