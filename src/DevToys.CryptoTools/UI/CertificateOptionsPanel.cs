using System.Globalization;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.UI;

internal sealed class CertificateOptionsPanel
{
    private readonly string _id;
    private readonly Dictionary<string, IUISingleLineTextInput> _text = [];
    private readonly Dictionary<string, IUISwitch> _flags = [];
    private readonly IUISelectDropDownList _algorithm;
    private readonly IUISelectDropDownList _hash;
    private readonly KeyFileInput _key;
    private readonly IUIMultiLineTextInput _customExtensions;
    internal IUIElement View { get; }
    internal event Action? Changed;
    internal string Algorithm => (string)_algorithm.SelectedItem!.Value!;

    private static readonly (string Name, int Value)[] KeyUsages =
    [
        ("DigitalSignature", KeyUsage.DigitalSignature), ("NonRepudiation", KeyUsage.NonRepudiation),
        ("KeyEncipherment", KeyUsage.KeyEncipherment), ("DataEncipherment", KeyUsage.DataEncipherment),
        ("KeyAgreement", KeyUsage.KeyAgreement), ("KeyCertSign", KeyUsage.KeyCertSign),
        ("CrlSign", KeyUsage.CrlSign), ("EncipherOnly", KeyUsage.EncipherOnly), ("DecipherOnly", KeyUsage.DecipherOnly)
    ];
    private static readonly (string Name, string Oid)[] ExtendedUsages =
    [
        ("ServerAuth", "1.3.6.1.5.5.7.3.1"), ("ClientAuth", "1.3.6.1.5.5.7.3.2"),
        ("CodeSigning", "1.3.6.1.5.5.7.3.3"), ("EmailProtection", "1.3.6.1.5.5.7.3.4"),
        ("IpsecEndSystem", "1.3.6.1.5.5.7.3.5"), ("IpsecTunnel", "1.3.6.1.5.5.7.3.6"),
        ("IpsecUser", "1.3.6.1.5.5.7.3.7"), ("TimeStamping", "1.3.6.1.5.5.7.3.8"),
        ("OcspSigning", "1.3.6.1.5.5.7.3.9"), ("DocumentSigning", "1.3.6.1.4.1.311.10.3.12"), ("AnyExtendedUsage", "2.5.29.37.0")
    ];

    internal CertificateOptionsPanel(string id, Func<Func<ValueTask>, ValueTask> execute, bool request)
    {
        _id = id;
        _algorithm = Choice("algorithm", "Algorithm", CertificateGenerator.Algorithms);
        _hash = Choice("hash", "Hash", ["Auto", "SHA256", "SHA384", "SHA512", "SM3"]);
        _algorithm.OnItemSelected(_ => UpdateHash());
        var preset = Choice("preset", "CertPreset", ["Custom", "TlsServer", "TlsClient", "CodeSigning", "DocumentSigning", "EmailProtection", "TimeStamping", "CertificateAuthority"], true);
        preset.OnItemSelected(item => { if (item is not null) ApplyPreset((string)item.Value!); });
        _key = new KeyFileInput(id + "-key", execute);
        _key.Editor.TextChanged += (_, _) => Changed?.Invoke();
        _algorithm.SelectedItemChanged += (_, _) => Changed?.Invoke();
        _hash.SelectedItemChanged += (_, _) => Changed?.Invoke();
        _customExtensions = MultiLineTextInput(id + "-CustomExtensions").Title(L("CertCustomExtensionsFormat")).ShowCommandBar();
        _customExtensions.TextChanged += (_, _) => Changed?.Invoke();
        var left = new List<IUIElement>
        {
            Heading("CertGeneral"), preset, _algorithm, _hash, Flag("RsaPss"), Heading("CertSubject"),
            Text("CommonName", "localhost"), Text("Organization"), Text("OrganizationalUnit"), Text("Country"),
            Text("State"), Text("Locality"), Text("SubjectOverride"), Heading("CertKeySource"),
            Label().Text(L("CertKeySourceHint")).AlignHorizontally(UIHorizontalAlignment.Left), _key.View
        };
        if (!request)
        {
            left.InsertRange(5, [Text("NotBefore", DateTime.UtcNow.AddMinutes(-5).ToString("yyyy-MM-dd HH:mm:ss'Z'", CultureInfo.InvariantCulture)),
                Text("NotAfter", DateTime.UtcNow.AddDays(365).ToString("yyyy-MM-dd HH:mm:ss'Z'", CultureInfo.InvariantCulture)), Text("SerialHex")]);
            left.Add(Text("IssuerOverride"));
        }
        var right = new List<IUIElement>
        {
            Heading("CertBasicConstraints"), Flag("IsCa"), Text("PathLength"), Flag("BasicConstraintsCritical", true),
            Heading("CertSan"), Flag("IncludeSan", true), Text("SanDns", "localhost"), Text("SanIp"), Text("SanEmail"), Text("SanUri"), Flag("SanCritical")
        };
        var ku = new List<IUIElement> { Heading("CertKeyUsage"), Flag("KeyUsageCritical", true) };
        ku.AddRange(KeyUsages.Select(usage => Flag(usage.Name, usage.Name == "DigitalSignature")));
        var eku = new List<IUIElement> { Heading("CertExtendedKeyUsage"), Flag("EnhancedKeyUsageCritical") };
        eku.AddRange(ExtendedUsages.Select(usage => Flag(usage.Name)));
        right.Add(Grid().Columns(Fraction(1), Fraction(1)).ColumnMediumSpacing().Cells(
            At(0, 0, Stack().Vertical().SmallSpacing().WithChildren([.. ku])), At(0, 1, Stack().Vertical().SmallSpacing().WithChildren([.. eku]))));
        right.Add(Text("CustomEkuOids"));
        right.Add(Heading("CertCustomExtensions"));
        right.Add(Text("CustomExtensionOid"));
        right.Add(Text("CustomExtensionDer"));
        right.Add(Flag("CustomExtensionCritical"));
        right.Add(Grid().Rows(new UIGridLength(150)).Cells(At(0, 0, _customExtensions)));
        View = Grid(id + "-options").Columns(Fraction(1), Fraction(1)).ColumnLargeSpacing().Cells(
            At(0, 0, Stack().Vertical().MediumSpacing().WithChildren([.. left]).AlignVertically(UIVerticalAlignment.Top)),
            At(0, 1, Stack().Vertical().MediumSpacing().WithChildren([.. right]).AlignVertically(UIVerticalAlignment.Top)));
        _flags["IncludeSan"].OnToggle(on =>
        {
            foreach (string field in new[] { "SanDns", "SanIp", "SanEmail", "SanUri" })
                if (on) _text[field].Enable(); else _text[field].Disable();
        });
        _flags["IsCa"].OnToggle(on => { if (on) _text["PathLength"].Enable(); else _text["PathLength"].Disable(); });
        _text["PathLength"].Disable();
        UpdateHash();
    }

    internal CertificateOptions Read()
    {
        string subject = Value("SubjectOverride");
        if (string.IsNullOrWhiteSpace(subject)) subject = BuildSubject();
        int? pathLength = !IsOn("IsCa") || string.IsNullOrWhiteSpace(Value("PathLength")) ? null : ParseInt(Value("PathLength"));
        string keyPem = string.IsNullOrWhiteSpace(_key.Editor.Text) ? "" : _key.GetPem();
        bool privateKey = keyPem.Contains("PRIVATE KEY", StringComparison.Ordinal);
        var custom = new List<CustomCertificateExtension>();
        if (!string.IsNullOrWhiteSpace(Value("CustomExtensionOid")))
            custom.Add(new CustomCertificateExtension(Value("CustomExtensionOid"), IsOn("CustomExtensionCritical"), Value("CustomExtensionDer")));
        foreach (string line in _customExtensions.Text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            string[] parts = line.Split('|', StringSplitOptions.TrimEntries);
            if (parts.Length != 3 || !bool.TryParse(parts[1], out bool critical)) throw new ArgumentException(L("CertInvalidExtension"));
            custom.Add(new CustomCertificateExtension(parts[0], critical, parts[2]));
        }
        return new CertificateOptions
        {
            Algorithm = Algorithm, Subject = subject, HashAlgorithm = (string)_hash.SelectedItem!.Value!, RsaPss = IsOn("RsaPss"),
            Issuer = Value("IssuerOverride"), SerialHex = Value("SerialHex"),
            NotBeforeUtc = DateValue("NotBefore", DateTime.UtcNow.AddMinutes(-5)), NotAfterUtc = DateValue("NotAfter", DateTime.UtcNow.AddDays(365)),
            IsCa = IsOn("IsCa"), PathLength = pathLength, BasicConstraintsCritical = IsOn("BasicConstraintsCritical"),
            KeyUsage = KeyUsages.Where(usage => IsOn(usage.Name)).Aggregate(0, (mask, usage) => mask | usage.Value),
            KeyUsageCritical = IsOn("KeyUsageCritical"), EnhancedKeyUsageCritical = IsOn("EnhancedKeyUsageCritical"),
            EnhancedKeyUsageOids = [.. ExtendedUsages.Where(usage => IsOn(usage.Name)).Select(usage => usage.Oid), .. Split(Value("CustomEkuOids"))],
            DnsNames = IsOn("IncludeSan") ? Split(Value("SanDns")) : [], IpAddresses = IsOn("IncludeSan") ? Split(Value("SanIp")) : [],
            EmailAddresses = IsOn("IncludeSan") ? Split(Value("SanEmail")) : [], Uris = IsOn("IncludeSan") ? Split(Value("SanUri")) : [],
            SanCritical = IsOn("SanCritical"), CustomExtensions = [.. custom],
            PrivateKeyPem = privateKey ? keyPem : "", PublicKeyPem = privateKey ? "" : keyPem
        };
    }

    internal void SetKey(string algorithm, string privateKey, string publicKey)
    {
        AsymmetricKeyParameter? key = null;
        if (!string.IsNullOrWhiteSpace(privateKey))
        {
            key = KeyGenerator.ReadKey(privateKey, true);
            if (!string.IsNullOrWhiteSpace(publicKey)
                && !CertificateRequestService.PublicKeysEqual(CertificateRequestService.PublicFromPrivate(key), KeyGenerator.ReadKey(publicKey, false)))
                throw new ArgumentException(L("KeyPairMismatch"));
        }
        else if (!string.IsNullOrWhiteSpace(publicKey)) key = KeyGenerator.ReadKey(publicKey, false);
        if (key is not null) algorithm = InferAlgorithm(key) ?? algorithm;
        var item = _algorithm.Items!.FirstOrDefault(item => Equals(item.Value, algorithm));
        if (item is not null) _algorithm.Select(item);
        _key.Editor.Text(string.IsNullOrEmpty(privateKey) ? publicKey : privateKey);
    }

    internal void ApplyRequest(CertificateRequestDetails details)
    {
        var subject = new X509Name(details.Subject);
        var fields = new (string Name, DerObjectIdentifier Oid)[]
        {
            ("CommonName", X509Name.CN), ("Organization", X509Name.O), ("OrganizationalUnit", X509Name.OU),
            ("Country", X509Name.C), ("State", X509Name.ST), ("Locality", X509Name.L)
        };
        foreach (var field in fields) _text[field.Name].Text(subject.GetValueList(field.Oid).FirstOrDefault() ?? "");
        bool needsOverride = subject.GetOidList().Any(oid => !fields.Any(field => field.Oid.Equals(oid)))
            || fields.Any(field => subject.GetValueList(field.Oid).Count > 1);
        _text["SubjectOverride"].Text(needsOverride ? details.Subject : "");
        _text["SanDns"].Text(string.Join(", ", details.DnsNames));
        _text["SanIp"].Text(string.Join(", ", details.IpAddresses));
        _text["SanEmail"].Text(string.Join(", ", details.EmailAddresses));
        _text["SanUri"].Text(string.Join(", ", details.Uris));
        var algorithm = InferAlgorithm(KeyGenerator.ReadKey(details.PublicKeyPem, false));
        var selected = _algorithm.Items!.FirstOrDefault(item => Equals(item.Value, algorithm));
        if (selected is not null) _algorithm.Select(selected);
        if (details.RequestedOptions is { } requested)
        {
            SetFlag("IsCa", requested.IsCa);
            _text["PathLength"].Text(requested.PathLength?.ToString(CultureInfo.InvariantCulture) ?? "");
            SetFlag("BasicConstraintsCritical", requested.BasicConstraintsCritical);
            SetFlag("IncludeSan", details.DnsNames.Length + details.IpAddresses.Length + details.EmailAddresses.Length + details.Uris.Length > 0);
            SetFlag("SanCritical", requested.SanCritical);
            SetFlag("KeyUsageCritical", requested.KeyUsageCritical);
            foreach (var usage in KeyUsages) SetFlag(usage.Name, (requested.KeyUsage & usage.Value) != 0);
            SetFlag("EnhancedKeyUsageCritical", requested.EnhancedKeyUsageCritical);
            foreach (var usage in ExtendedUsages) SetFlag(usage.Name, requested.EnhancedKeyUsageOids.Contains(usage.Oid));
            _text["CustomEkuOids"].Text(string.Join(", ", requested.EnhancedKeyUsageOids.Except(ExtendedUsages.Select(usage => usage.Oid))));
            _text["CustomExtensionOid"].Text(""); _text["CustomExtensionDer"].Text("");
            _customExtensions.Text(string.Join("\n", requested.CustomExtensions.Select(extension => $"{extension.Oid}|{extension.Critical.ToString().ToLowerInvariant()}|{extension.DerBase64}")));
        }
    }

    private void SetFlag(string name, bool on) { if (on) _flags[name].On(); else _flags[name].Off(); }

    private static string? InferAlgorithm(AsymmetricKeyParameter key)
    {
        if (key is RsaKeyParameters rsa) return "RSA-" + rsa.Modulus.BitLength.ToString(CultureInfo.InvariantCulture);
        if (key is Ed25519PrivateKeyParameters or Ed25519PublicKeyParameters) return "Ed25519";
        if (key is Ed448PrivateKeyParameters or Ed448PublicKeyParameters) return "Ed448";
        if (key is ECKeyParameters ec)
        {
            foreach (string algorithm in CertificateGenerator.Algorithms.Where(value => value.StartsWith("ECDSA-", StringComparison.Ordinal) || value == "SM2"))
            {
                var domain = EcDomains.ForAlgorithm(algorithm);
                if (ec.Parameters.Curve.Equals(domain.Curve) && ec.Parameters.G.Equals(domain.G) && ec.Parameters.N.Equals(domain.N)) return algorithm;
            }
        }
        return null;
    }

    private string BuildSubject()
    {
        var fields = new (string Name, DerObjectIdentifier Oid)[]
        {
            ("CommonName", X509Name.CN), ("Organization", X509Name.O), ("OrganizationalUnit", X509Name.OU),
            ("Country", X509Name.C), ("State", X509Name.ST), ("Locality", X509Name.L)
        };
        var order = new List<DerObjectIdentifier>();
        var values = new Dictionary<DerObjectIdentifier, string>();
        foreach (var field in fields)
        {
            string value = Value(field.Name);
            if (string.IsNullOrWhiteSpace(value)) continue;
            order.Add(field.Oid); values[field.Oid] = value;
        }
        return new X509Name(order, values).ToString();
    }

    private void ApplyPreset(string preset)
    {
        foreach (var usage in KeyUsages) _flags[usage.Name].Off();
        foreach (var usage in ExtendedUsages) _flags[usage.Name].Off();
        _flags["IsCa"].Off();
        _flags["DigitalSignature"].On();
        if (preset == "TlsServer") { _flags["ServerAuth"].On(); _flags["KeyEncipherment"].On(); }
        if (preset == "TlsClient") _flags["ClientAuth"].On();
        if (preset == "CodeSigning") _flags["CodeSigning"].On();
        if (preset is "DocumentSigning" or "EmailProtection" or "TimeStamping") _flags[preset].On();
        if (preset == "CertificateAuthority") { _flags["IsCa"].On(); _flags["KeyCertSign"].On(); _flags["CrlSign"].On(); }
    }

    private void UpdateHash()
    {
        bool intrinsic = Algorithm is "SM2" or "Ed25519" or "Ed448";
        _hash.WithItems((intrinsic ? new[] { "Auto" } : new[] { "Auto", "SHA256", "SHA384", "SHA512" }).Select(value => Item(value, value)).ToArray()).Select(0);
        if (intrinsic) _hash.Disable(); else _hash.Enable();
        if (Algorithm.StartsWith("RSA-", StringComparison.Ordinal)) _flags["RsaPss"].Enable();
        else _flags["RsaPss"].Off().Disable();
    }

    private IUISingleLineTextInput Text(string name, string value = "")
    {
        var input = SingleLineTextInput(_id + "-" + name).Title(L("Cert" + name)).Text(value).ShowCommandBar();
        input.TextChanged += (_, _) => Changed?.Invoke();
        _text[name] = input; return input;
    }
    private IUIElement Flag(string name, bool on = false)
    {
        var flag = Switch(_id + "-" + name).OnText(L("CertEnabled")).OffText(L("CertDisabled"));
        if (on) flag.On();
        flag.IsOnChanged += (_, _) => Changed?.Invoke();
        _flags[name] = flag;
        return Setting().Title(L("Cert" + name)).InteractiveElement(flag);
    }
    private IUISelectDropDownList Choice(string name, string title, string[] values, bool localized = false) => SelectDropDownList(_id + "-" + name)
        .Title(L(title)).WithItems(values.Select(value => Item(localized ? L("Cert" + value) : value, value)).ToArray()).Select(0).AlignHorizontally(UIHorizontalAlignment.Left);
    private static IUILabel Heading(string key) => Label().Text(L(key)).Style(UILabelStyle.BodyStrong).AlignHorizontally(UIHorizontalAlignment.Left);
    private string Value(string name) => _text.TryGetValue(name, out var field) ? field.Text : "";
    private bool IsOn(string name) => _flags[name].IsOn;
    private static string[] Split(string value) => value.Split([',', '\r', '\n'], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
    private static int ParseInt(string value) => int.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out int result) ? result : throw new ArgumentException(L("CertInvalidNumber"));
    private DateTime DateValue(string name, DateTime fallback) => string.IsNullOrWhiteSpace(Value(name)) ? fallback
        : DateTimeOffset.TryParse(Value(name), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var value)
            ? value.UtcDateTime : throw new ArgumentException(L("CertInvalidDate"));
    private static IUIGridCell At(int row, int column, IUIElement element) => Cell().Row(row).Column(column).WithChild(element);
}
