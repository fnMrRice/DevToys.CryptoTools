using System.ComponentModel.Composition;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.UI;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tools;

[Export(typeof(IGuiTool))]
[Name("DevToys.CryptoTools.CertificateRequestTool")]
[ToolDisplayInformation(
    IconFontName = "FluentSystemIcons", IconGlyph = '\uE8C9',
    GroupName = PredefinedCommonToolGroupNames.Generators,
    ResourceManagerAssemblyIdentifier = nameof(CryptoToolsResourceAssemblyIdentifier),
    ResourceManagerBaseName = ResourceBaseName,
    ShortDisplayTitleResourceName = "CsrTitle", LongDisplayTitleResourceName = "CsrTitle",
    DescriptionResourceName = "CsrDescription", AccessibleNameResourceName = "CsrTitle")]
internal sealed class CertificateRequestTool : CryptoToolBase
{
    private readonly CertificateOptionsPanel _options;
    private readonly IUIMultiLineTextInput _output = MultiLineTextInput("csr-output").Title(L("Csr")).ReadOnly().ShowCommandBar().Extendable();
    private readonly IUIMultiLineTextInput _privateKey = MultiLineTextInput("csr-private-output").Title(L("PrivateKey")).ReadOnly().ShowCommandBar().Extendable();
    private readonly WorkflowContainer _workflow;

    protected override IUIElement BuildLayout() => _workflow.Root;

    public CertificateRequestTool()
    {
        _options = new CertificateOptionsPanel("csr", ExecuteAsync, true);
        _options.Changed += () => { _output.Text(""); _privateKey.Text(""); };
        var actions = Stack().Horizontal().SmallSpacing().AlignHorizontally(UIHorizontalAlignment.Left).WithChildren(
            CreateActionButton(L("GenerateCsr"), Generate, "csr-generate").AccentAppearance(),
            CreateActionButton(L("CertIssueCsr"), SendToCertificate, "csr-issue"),
            CreateActionButton(L("Clear"), () => { _output.Text(""); _privateKey.Text(""); }, "csr-clear-output"));
        var results = Grid().Rows(new UIGridLength(350)).AlignVertically(UIVerticalAlignment.Top).Cells(Cell().WithChild(
            SplitGrid("csr-results").Vertical().WithLeftPaneChild(_output).WithRightPaneChild(_privateKey)));
        var layout = Stack("csr-layout").Vertical().MediumSpacing().AlignVertically(UIVerticalAlignment.Top).WithChildren(
            Label().Text(L("CsrBuilderHint")).AlignHorizontally(UIHorizontalAlignment.Left), _options.View, actions, results, Status);
        _workflow = new WorkflowContainer(layout);
    }

    private void Generate()
    {
        _output.Text(""); _privateKey.Text("");
        var result = CertificateRequestService.Generate(_options.Read());
        _output.Text(result.Document); _privateKey.Text(result.PrivateKey);
    }

    private void SendToCertificate()
    {
        if (string.IsNullOrWhiteSpace(_output.Text)) Generate();
        _workflow.Open(L("CertTitle"), new CertificateGeneratorTool(), DraftTransfer.CsrDataType, new CsrDraft(_output.Text, _privateKey.Text));
    }

    public override void OnDataReceived(string dataTypeName, object? parsedData)
    {
        if (dataTypeName == DraftTransfer.KeyPairDataType && parsedData is KeyPairDraft key)
            _options.SetKey(key.Algorithm, key.PrivateKey, key.PublicKey);
    }
}
