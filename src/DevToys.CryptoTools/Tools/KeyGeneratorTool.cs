using System.ComponentModel.Composition;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.UI;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tools;

[Export(typeof(IGuiTool))]
[Name("DevToys.CryptoTools.KeyGeneratorTool")]
[ToolDisplayInformation(
    IconFontName = "FluentSystemIcons", IconGlyph = '\uE8C9',
    GroupName = PredefinedCommonToolGroupNames.Generators,
    ResourceManagerAssemblyIdentifier = nameof(CryptoToolsResourceAssemblyIdentifier),
    ResourceManagerBaseName = ResourceBaseName,
    ShortDisplayTitleResourceName = "KeyTitle",
    LongDisplayTitleResourceName = "KeyTitle",
    DescriptionResourceName = "KeyDescription",
    AccessibleNameResourceName = "KeyTitle")]
internal sealed class KeyGeneratorTool : CryptoToolBase
{
    private readonly WorkflowContainer _workflow;
    protected override IUIElement BuildLayout() => _workflow.Root;

    public KeyGeneratorTool()
    {
        var algorithm = SelectDropDownList("key-algorithm")
            .WithItems(KeyGenerator.AsymmetricAlgorithms.Select(a => Item(a, a)).ToArray()).Select(0);
        var configuration = Setting("key-algorithm-setting")
            .Title(L("Algorithm")).Description(L("KeyNote")).Icon("FluentSystemIcons", '\uE670')
            .InteractiveElement(algorithm);
        var publicKey = MultiLineTextInput("key-public").Title(L("PublicKey")).ReadOnly().ShowCommandBar().Extendable();
        var privateKey = MultiLineTextInput("key-private").Title(L("PrivateKey")).ReadOnly().ShowCommandBar().Extendable();
        KeyPairDraft? draft = null;
        var generate = CreateActionButton(L("Generate"), () =>
        {
            draft = null;
            publicKey.Text(""); privateKey.Text("");
            var result = KeyGenerator.Generate(Selected(algorithm));
            publicKey.Text(result.PublicKey);
            privateKey.Text(result.PrivateKey);
            if (result.PrivateKey.Length > 0) draft = new KeyPairDraft(Selected(algorithm), result.PublicKey, result.PrivateKey);
        }, "key-generate").AccentAppearance();
        var send = CreateActionButton(L("SendToCsr"), () =>
        {
            if (draft is null) throw new ArgumentException(L("NoSigningKey"));
            OpenRequest(draft);
        }, "key-send-csr");
        var clear = CreateActionButton(L("Clear"), () => { draft = null; publicKey.Text(""); privateKey.Text(""); }, "key-clear");
        var actions = Stack("key-actions").Horizontal().SmallSpacing()
            .AlignHorizontally(UIHorizontalAlignment.Left).WithChildren(generate, send, clear);
        var editors = SplitGrid("key-editors").Vertical().WithLeftPaneChild(privateKey).WithRightPaneChild(publicKey);
        var layout = Grid("key-layout").Rows(Auto, Auto, Fraction(1), Auto).RowLargeSpacing().Cells(
            Cell().Row(0).WithChild(configuration), Cell().Row(1).WithChild(actions),
            Cell().Row(2).WithChild(editors), Cell().Row(3).WithChild(Status));
        _workflow = new WorkflowContainer(layout);
    }

    private void OpenRequest(KeyPairDraft draft) => _workflow.Open(L("CsrTitle"), new CertificateRequestTool(), DraftTransfer.KeyPairDataType, draft);
}
