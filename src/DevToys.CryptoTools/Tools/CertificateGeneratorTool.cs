using System.ComponentModel.Composition;
using System.Security.Cryptography;
using System.Text;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.UI;
using Org.BouncyCastle.X509;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tools;

[Export(typeof(IGuiTool))]
[Name("DevToys.CryptoTools.CertificateGeneratorTool")]
[ToolDisplayInformation(
    IconFontName = "FluentSystemIcons", IconGlyph = '\uE8C9',
    GroupName = PredefinedCommonToolGroupNames.Generators,
    ResourceManagerAssemblyIdentifier = nameof(CryptoToolsResourceAssemblyIdentifier),
    ResourceManagerBaseName = ResourceBaseName,
    ShortDisplayTitleResourceName = "CertTitle", LongDisplayTitleResourceName = "CertTitle",
    DescriptionResourceName = "CertDescription", AccessibleNameResourceName = "CertTitle")]
internal sealed class CertificateGeneratorTool : CryptoToolBase
{
    private readonly CertificateOptionsPanel _options;
    private readonly IUIMultiLineTextInput _csr = MultiLineTextInput("cert-csr").Title(L("Csr")).ShowCommandBar().Extendable();
    private readonly IUIMultiLineTextInput _issuerCertificate = MultiLineTextInput("cert-issuer-certificate").Title(L("CertIssuerCertificate")).ShowCommandBar().Extendable();
    private readonly KeyFileInput _issuerKey;
    private readonly IUISwitch _useIssuer = Switch("cert-use-issuer").OnText(L("CertUseIssuer")).OffText(L("CertUseIssuer"));
    private readonly IUIMultiLineTextInput _output = MultiLineTextInput("cert-output").Title(L("Certificate")).ReadOnly().ShowCommandBar().Extendable();
    private readonly IUIMultiLineTextInput _privateKey = MultiLineTextInput("cert-private-output").Title(L("PrivateKey")).ReadOnly().ShowCommandBar().Extendable();
    private readonly IUIElement _layout;

    protected override IUIElement BuildLayout() => _layout;

    public CertificateGeneratorTool()
    {
        _options = new CertificateOptionsPanel("cert", ExecuteAsync, false);
        _issuerKey = new KeyFileInput("cert-issuer-key", ExecuteAsync);
        var csrFile = FileSelector("cert-csr-file").CanSelectOneFile().LimitFileTypesTo("pem", "csr", "der")
            .OnFilesSelected(files => files.Length == 0 ? ValueTask.CompletedTask : ExecuteAsync(() => ImportCsr(files)));
        var issuerFile = FileSelector("cert-issuer-file").CanSelectOneFile().LimitFileTypesTo("pem", "crt", "cer", "der")
            .OnFilesSelected(files => files.Length == 0 ? ValueTask.CompletedTask : ExecuteAsync(() => ImportIssuer(files)));
        var issuerPanel = Grid("cert-issuer-panel").Columns(Fraction(1), Fraction(1)).ColumnLargeSpacing().Cells(
            At(0, 0, Stack().Vertical().SmallSpacing().WithChildren(issuerFile, _issuerCertificate)), At(0, 1, _issuerKey.View)).Hide();
        _useIssuer.OnToggle(on => { if (on) issuerPanel.Show(); else issuerPanel.Hide(); });
        var requestPanel = Grid("cert-request-panel").Columns(Fraction(1), Fraction(1)).ColumnLargeSpacing().Cells(
            At(0, 0, Stack().Vertical().SmallSpacing().WithChildren(Label().Text(L("CertCsrImportHint")), csrFile,
                CreateActionButton(L("CertReadCsr"), ReadCsr, "cert-read-csr"))), At(0, 1, _csr));
        var actions = Stack().Horizontal().SmallSpacing().AlignHorizontally(UIHorizontalAlignment.Left).WithChildren(
            CreateActionButton(L("GenerateCert"), Generate, "cert-generate").AccentAppearance(),
            CreateActionButton(L("Clear"), () => { _output.Text(""); _privateKey.Text(""); _csr.Text(""); }, "cert-clear-output"));
        var results = Grid().Rows(new UIGridLength(350)).Cells(At(0, 0,
            SplitGrid("cert-results").Vertical().WithLeftPaneChild(_output).WithRightPaneChild(_privateKey)));
        _layout = Stack("cert-layout").Vertical().MediumSpacing().WithChildren(
            _options.View, Label().Text(L("CertRequestSection")).Style(UILabelStyle.BodyStrong), requestPanel,
            _useIssuer, issuerPanel, actions, results, Status);
    }

    private void Generate()
    {
        _output.Text(""); _privateKey.Text("");
        var options = _options.Read();
        if (!string.IsNullOrWhiteSpace(_csr.Text))
            options = options with { CsrPem = CertificateRequestService.Normalize(Encoding.UTF8.GetBytes(_csr.Text)) };
        if (_useIssuer.IsOn)
            options = options with { IssuerCertificatePem = NormalizeCertificate(Encoding.UTF8.GetBytes(_issuerCertificate.Text)), IssuerPrivateKeyPem = _issuerKey.GetPem() };
        var generated = CertificateGenerator.Generate(options);
        _output.Text(generated.Document); _privateKey.Text(generated.PrivateKey);
    }

    private void ReadCsr()
    {
        var bytes = Encoding.UTF8.GetBytes(_csr.Text);
        string normalized = CertificateRequestService.Normalize(bytes);
        var details = CertificateRequestService.Inspect(bytes);
        _csr.Text(normalized); _options.ApplyRequest(details);
    }

    private async ValueTask ImportCsr(SandboxedFileReader[] files)
    {
        _csr.Text(""); _output.Text(""); _privateKey.Text("");
        byte[] bytes = await FileImport.ReadAsync(files);
        try { _csr.Text(CertificateRequestService.Normalize(bytes)); _options.ApplyRequest(CertificateRequestService.Inspect(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private async ValueTask ImportIssuer(SandboxedFileReader[] files)
    {
        _issuerCertificate.Text("");
        byte[] bytes = await FileImport.ReadAsync(files);
        try { _issuerCertificate.Text(NormalizeCertificate(bytes)); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static string NormalizeCertificate(byte[] bytes)
    {
        var certificate = CertificateGenerator.ReadCertificate(bytes);
        return PemEncoding.WriteString("CERTIFICATE", certificate.GetEncoded());
    }

    public override void OnDataReceived(string dataTypeName, object? parsedData)
    {
        if (dataTypeName == DraftTransfer.KeyPairDataType && parsedData is KeyPairDraft key)
            _options.SetKey(key.Algorithm, key.PrivateKey, key.PublicKey);
        if (dataTypeName == DraftTransfer.CsrDataType && parsedData is CsrDraft csr)
        {
            Execute(() =>
            {
                _csr.Text(csr.RequestPem); ReadCsr();
                if (!string.IsNullOrEmpty(csr.PrivateKey)) _options.SetKey("", csr.PrivateKey, "");
            });
        }
    }

    private static IUIGridCell At(int row, int column, IUIElement child) => Cell().Row(row).Column(column).WithChild(child);
}
