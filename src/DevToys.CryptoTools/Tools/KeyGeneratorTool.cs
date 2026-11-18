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
        Note(L("KeyNote"));
        var algorithm = Add(SelectDropDownList("key-algorithm").Title(L("Algorithm"))
            .WithItems(KeyGenerator.Algorithms.Select(a => Item(a, a)).ToArray()).Select(0).AlignHorizontally(UIHorizontalAlignment.Left));
        var publicKey = Add(MultiLineTextInput("key-public").Title(L("PublicKey")).ReadOnly());
        var privateKey = Add(MultiLineTextInput("key-private").Title(L("PrivateKey")).ReadOnly());
        var symmetricKey = Add(MultiLineTextInput("key-symmetric").Title(L("SymKey")).ReadOnly());
        KeyPairDraft? draft = null;
        Add(CreateActionButton(L("Generate"), () =>
        {
            draft = null;
            publicKey.Text(""); privateKey.Text(""); symmetricKey.Text("");
            var result = KeyGenerator.Generate(Selected(algorithm));
            publicKey.Text(result.PublicKey);
            privateKey.Text(result.PrivateKey);
            symmetricKey.Text(result.SymmetricKey);
            if (result.PrivateKey.Length > 0) draft = new KeyPairDraft(Selected(algorithm), result.PublicKey, result.PrivateKey);
        }, "key-generate"));
        var send = CreateActionButton(L("SendToCsr"), () =>
        {
            if (draft is null) throw new ArgumentException(L("NoSigningKey"));
            OpenRequest(draft);
        }, "key-send-csr");
        Add(send);
        ActionButton(L("Clear"), () => { draft = null; publicKey.Text(""); privateKey.Text(""); symmetricKey.Text(""); });
        _workflow = new WorkflowContainer(base.BuildLayout());
    }

    private void OpenRequest(KeyPairDraft draft) => _workflow.Open(L("CsrTitle"), new CertificateRequestTool(), DraftTransfer.KeyPairDataType, draft);
}
