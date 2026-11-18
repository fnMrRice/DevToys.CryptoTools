using System.Net;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace DevToys.CryptoTools.Cryptography;

internal static class CertificateRequestService
{
    internal static CertificateMaterial Generate(CertificateOptions options)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(options.Subject);
        var material = GetKeyMaterial(options);
        var signer = SignatureFactory(material.Private, options);
        var extensions = BuildExtensions(options);
        var attribute = new AttributePkcs(PkcsObjectIdentifiers.Pkcs9AtExtensionRequest, new DerSet(extensions));
        var request = new Pkcs10CertificationRequest(signer, new X509Name(options.Subject), material.Public, new DerSet(attribute));
        return new(PemEncoding.WriteString("CERTIFICATE REQUEST", request.GetDerEncoded()), material.PrivatePem);
    }

    internal static string Normalize(byte[] data) => PemEncoding.WriteString("CERTIFICATE REQUEST", Parse(data).GetDerEncoded());

    internal static CertificateRequestDetails Inspect(byte[] data)
    {
        try { return InspectCore(data); }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            throw new ArgumentException(L("InvalidCsr"), ex);
        }
    }

    private static CertificateRequestDetails InspectCore(byte[] data)
    {
        var request = Parse(data);
        var requested = request.GetRequestedExtensions();
        var names = GeneralNames.GetInstance(requested?.GetExtensionParsedValue(X509Extensions.SubjectAlternativeName));
        var dns = new List<string>();
        var ip = new List<string>();
        var email = new List<string>();
        var uri = new List<string>();
        foreach (var name in names?.GetNames() ?? [])
        {
            switch (name.TagNo)
            {
                case GeneralName.DnsName: dns.Add(DerIA5String.GetInstance(name.Name).GetString()); break;
                case GeneralName.Rfc822Name: email.Add(DerIA5String.GetInstance(name.Name).GetString()); break;
                case GeneralName.UniformResourceIdentifier: uri.Add(DerIA5String.GetInstance(name.Name).GetString()); break;
                case GeneralName.IPAddress: ip.Add(new IPAddress(Asn1OctetString.GetInstance(name.Name).GetOctets()).ToString()); break;
            }
        }
        string subject = request.GetCertificationRequestInfo().Subject.ToString();
        string publicKey = ExportPublic(request.GetPublicKey());
        var constraints = BasicConstraints.GetInstance(requested?.GetExtensionParsedValue(X509Extensions.BasicConstraints));
        var usage = KeyUsage.GetInstance(requested?.GetExtensionParsedValue(X509Extensions.KeyUsage));
        var enhanced = ExtendedKeyUsage.GetInstance(requested?.GetExtensionParsedValue(X509Extensions.ExtendedKeyUsage));
        if (constraints?.PathLenConstraint is { } path && (path.SignValue < 0 || path.BitLength > 31)) throw new ArgumentException();
        var known = new HashSet<string>
        {
            X509Extensions.BasicConstraints.Id, X509Extensions.KeyUsage.Id, X509Extensions.ExtendedKeyUsage.Id,
            X509Extensions.SubjectAlternativeName.Id, X509Extensions.SubjectKeyIdentifier.Id, X509Extensions.AuthorityKeyIdentifier.Id
        };
        var custom = new List<CustomCertificateExtension>();
        foreach (var oid in requested?.GetExtensionOids() ?? [])
        {
            if (known.Contains(oid.Id)) continue;
            var extension = requested!.GetExtension(oid);
            // Preserve the DER value, not the containing OCTET STRING wrapper.
            byte[] der = extension.Value.GetOctets();
            _ = Asn1Object.FromByteArray(der);
            custom.Add(new(oid.Id, extension.IsCritical, Convert.ToBase64String(der)));
        }
        bool Critical(DerObjectIdentifier oid) => requested?.GetExtension(oid)?.IsCritical == true;
        var options = new CertificateOptions
        {
            Subject = subject, PublicKeyPem = publicKey, IsCa = constraints?.IsCA() == true,
            PathLength = constraints?.PathLenConstraint?.IntValue, BasicConstraintsCritical = Critical(X509Extensions.BasicConstraints),
            KeyUsage = usage?.IntValue ?? 0, KeyUsageCritical = Critical(X509Extensions.KeyUsage),
            EnhancedKeyUsageOids = enhanced?.GetAllUsages().Select(oid => oid.Id).ToArray() ?? [],
            EnhancedKeyUsageCritical = Critical(X509Extensions.ExtendedKeyUsage), SanCritical = Critical(X509Extensions.SubjectAlternativeName),
            DnsNames = [.. dns], IpAddresses = [.. ip], EmailAddresses = [.. email], Uris = [.. uri], CustomExtensions = [.. custom]
        };
        return new(subject, publicKey, [.. dns], [.. ip], [.. email], [.. uri], options);
    }

    internal static Pkcs10CertificationRequest Parse(byte[] data)
    {
        try
        {
            byte[] der = DecodePemOrDer(data, "CERTIFICATE REQUEST", "NEW CERTIFICATE REQUEST");
            var request = new Pkcs10CertificationRequest(der);
            if (!request.Verify()) throw new ArgumentException();
            return request;
        }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            throw new ArgumentException(L("InvalidCsr"), ex);
        }
    }

    internal static byte[] DecodePemOrDer(byte[] data, params string[] labels)
    {
        string text = Encoding.UTF8.GetString(data).TrimStart('\uFEFF', ' ', '\r', '\n', '\t');
        if (!text.StartsWith("-----BEGIN", StringComparison.Ordinal)) return data;
        var fields = PemEncoding.Find(text);
        if (!labels.Contains(text[fields.Label])) throw new ArgumentException();
        return Convert.FromBase64String(text[fields.Base64Data]);
    }

    internal static (AsymmetricKeyParameter Public, AsymmetricKeyParameter Private, string PrivatePem) GetKeyMaterial(CertificateOptions options, bool requireSigning = true)
    {
        string privatePem = options.PrivateKeyPem;
        if (string.IsNullOrWhiteSpace(privatePem))
        {
            var generated = KeyGenerator.Generate(options.Algorithm);
            if (string.IsNullOrEmpty(generated.PrivateKey)) throw new ArgumentException(L("InvalidKey"));
            privatePem = generated.PrivateKey;
        }
        var privateKey = KeyGenerator.ReadKey(privatePem, true);
        var publicKey = PublicFromPrivate(privateKey);
        if (!string.IsNullOrWhiteSpace(options.PublicKeyPem))
        {
            var supplied = KeyGenerator.ReadKey(options.PublicKeyPem, false);
            if (!PublicKeysEqual(publicKey, supplied)) throw new ArgumentException(L("KeyPairMismatch"));
        }
        // Validate signer capability immediately; XDH keys cannot sign certificate requests.
        if (requireSigning) _ = SignatureFactory(privateKey, options);
        return (publicKey, privateKey, privatePem);
    }

    internal static AsymmetricKeyParameter PublicFromPrivate(AsymmetricKeyParameter key) => key switch
    {
        RsaPrivateCrtKeyParameters rsa => new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent),
        ECPrivateKeyParameters ec => new ECPublicKeyParameters(ec.AlgorithmName, ec.Parameters.G.Multiply(ec.D), ec.Parameters),
        Ed25519PrivateKeyParameters ed => ed.GeneratePublicKey(),
        Ed448PrivateKeyParameters ed => ed.GeneratePublicKey(),
        X25519PrivateKeyParameters x => x.GeneratePublicKey(),
        X448PrivateKeyParameters x => x.GeneratePublicKey(),
        _ => throw new ArgumentException(L("UnsupportedSignatureAlgorithm"))
    };

    internal static string ExportPublic(AsymmetricKeyParameter key) => PemEncoding.WriteString("PUBLIC KEY", SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(key).GetDerEncoded());
    internal static bool PublicKeysEqual(AsymmetricKeyParameter a, AsymmetricKeyParameter b) =>
        CryptographicOperations.FixedTimeEquals(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(a).GetDerEncoded(), SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(b).GetDerEncoded());

    internal static Asn1SignatureFactory SignatureFactory(AsymmetricKeyParameter key, CertificateOptions options)
    {
        string hash = options.HashAlgorithm.ToUpperInvariant();
        string algorithm;
        if (key is Ed25519PrivateKeyParameters or Ed448PrivateKeyParameters)
        {
            if (hash != "AUTO" || options.RsaPss) throw new ArgumentException(L("UnsupportedSignatureAlgorithm"));
            algorithm = key is Ed25519PrivateKeyParameters ? "Ed25519" : "Ed448";
        }
        else if (key is ECPrivateKeyParameters ec && ec.PublicKeyParamSet?.Id == "1.2.156.10197.1.301")
        {
            if (hash is not ("AUTO" or "SM3") || options.RsaPss) throw new ArgumentException(L("UnsupportedSignatureAlgorithm"));
            algorithm = "SM3withSM2";
        }
        else
        {
            if (hash == "AUTO") hash = key is ECPrivateKeyParameters ecKey
                ? ecKey.Parameters.Curve.FieldSize > 384 ? "SHA512" : ecKey.Parameters.Curve.FieldSize > 256 ? "SHA384" : "SHA256"
                : "SHA256";
            if (hash is not ("SHA256" or "SHA384" or "SHA512")) throw new ArgumentException(L("UnsupportedSignatureAlgorithm"));
            algorithm = key switch
            {
                RsaPrivateCrtKeyParameters => hash + (options.RsaPss ? "withRSAandMGF1" : "withRSA"),
                ECPrivateKeyParameters when !options.RsaPss => hash + "withECDSA",
                _ => throw new ArgumentException(L("UnsupportedSignatureAlgorithm"))
            };
        }
        return new Asn1SignatureFactory(algorithm, key, new SecureRandom());
    }

    internal static X509Extensions BuildExtensions(CertificateOptions options)
    {
        const int allUsages = KeyUsage.DigitalSignature | KeyUsage.NonRepudiation | KeyUsage.KeyEncipherment | KeyUsage.DataEncipherment
            | KeyUsage.KeyAgreement | KeyUsage.KeyCertSign | KeyUsage.CrlSign | KeyUsage.EncipherOnly | KeyUsage.DecipherOnly;
        if ((options.KeyUsage & ~allUsages) != 0 || options.PathLength < 0 || (!options.IsCa && options.PathLength is not null)
            || (!options.IsCa && (options.KeyUsage & KeyUsage.KeyCertSign) != 0)
            || ((options.KeyUsage & (KeyUsage.EncipherOnly | KeyUsage.DecipherOnly)) != 0 && (options.KeyUsage & KeyUsage.KeyAgreement) == 0))
            throw new ArgumentException(L("InvalidCertificateOptions"));
        var generator = new X509ExtensionsGenerator();
        generator.AddExtension(X509Extensions.BasicConstraints, options.BasicConstraintsCritical,
            options.IsCa ? options.PathLength.HasValue ? new BasicConstraints(options.PathLength.Value) : new BasicConstraints(true) : new BasicConstraints(false));
        if (options.KeyUsage != 0) generator.AddExtension(X509Extensions.KeyUsage, options.KeyUsageCritical, new KeyUsage(options.KeyUsage));
        if (options.EnhancedKeyUsageOids.Length > 0)
            generator.AddExtension(X509Extensions.ExtendedKeyUsage, options.EnhancedKeyUsageCritical,
                new ExtendedKeyUsage(options.EnhancedKeyUsageOids.Distinct().Select(oid => KeyPurposeID.GetInstance(new DerObjectIdentifier(oid))).ToArray()));
        var names = new List<GeneralName>();
        try
        {
            var idn = new System.Globalization.IdnMapping();
            foreach (string dns in options.DnsNames)
            {
                string normalized = dns.StartsWith("*.", StringComparison.Ordinal) ? "*." + idn.GetAscii(dns[2..]) : idn.GetAscii(dns);
                if (Uri.CheckHostName(normalized.StartsWith("*.", StringComparison.Ordinal) ? normalized[2..] : normalized) != UriHostNameType.Dns)
                    throw new ArgumentException();
                names.Add(new GeneralName(GeneralName.DnsName, normalized));
            }
            foreach (string ip in options.IpAddresses)
            {
                if (!IPAddress.TryParse(ip, out _)) throw new ArgumentException();
                names.Add(new GeneralName(GeneralName.IPAddress, ip));
            }
            foreach (string email in options.EmailAddresses)
            {
                if (!System.Net.Mail.MailAddress.TryCreate(email, out var address) || address.Address != email || email.Any(c => c > 127)) throw new ArgumentException();
                names.Add(new GeneralName(GeneralName.Rfc822Name, email));
            }
            foreach (string uri in options.Uris)
            {
                if (!Uri.TryCreate(uri, UriKind.Absolute, out var address)) throw new ArgumentException();
                names.Add(new GeneralName(GeneralName.UniformResourceIdentifier, address.AbsoluteUri));
            }
        }
        catch (ArgumentException ex) { throw new ArgumentException(L("InvalidSan"), ex); }
        if (names.Count > 0) generator.AddExtension(X509Extensions.SubjectAlternativeName, options.SanCritical, new GeneralNames([.. names]));
        var reserved = new HashSet<string>
        {
            X509Extensions.BasicConstraints.Id, X509Extensions.KeyUsage.Id, X509Extensions.ExtendedKeyUsage.Id,
            X509Extensions.SubjectAlternativeName.Id, X509Extensions.SubjectKeyIdentifier.Id, X509Extensions.AuthorityKeyIdentifier.Id
        };
        foreach (var extension in options.CustomExtensions)
        {
            try
            {
                if (!reserved.Add(extension.Oid)) throw new ArgumentException();
                var oid = new DerObjectIdentifier(extension.Oid);
                byte[] encoded = Convert.FromBase64String(extension.DerBase64);
                _ = Asn1Object.FromByteArray(encoded);
                generator.AddExtension(oid, extension.Critical, encoded);
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException or IOException)
            {
                throw new ArgumentException(L("InvalidCustomExtension"), ex);
            }
        }
        return generator.Generate();
    }
}
