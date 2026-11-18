using System.ComponentModel.Composition;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.UI;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tools;

[Export(typeof(IGuiTool))]
[Name("DevToys.CryptoTools.KeyGeneratorTool")]
[ToolDisplayInformation(
    IconFontName = "FluentSystemIcons", IconGlyph = '\uE670',
    GroupName = PredefinedCommonToolGroupNames.Generators,
    ResourceManagerAssemblyIdentifier = nameof(CryptoToolsResourceAssemblyIdentifier),
    ResourceManagerBaseName = ResourceBaseName,
    ShortDisplayTitleResourceName = "KeyTitle",
    LongDisplayTitleResourceName = "KeyTitle",
    DescriptionResourceName = "KeyDescription",
    AccessibleNameResourceName = "KeyTitle")]
internal sealed class KeyGeneratorTool : CryptoToolBase
{
    public KeyGeneratorTool()
    {
        Note(L("KeyNote"));
        var algorithm = Choice(L("Algorithm"), KeyGenerator.Algorithms);
        var publicKey = Editor(L("PublicKey"), true);
        var privateKey = Editor(L("PrivateKey"), true);
        var symmetricKey = Editor(L("SymKey"), true);
        ActionButton(L("Generate"), () =>
        {
            publicKey.Text(""); privateKey.Text(""); symmetricKey.Text("");
            var result = KeyGenerator.Generate(Selected(algorithm));
            publicKey.Text(result.PublicKey);
            privateKey.Text(result.PrivateKey);
            symmetricKey.Text(result.SymmetricKey);
        });
        ActionButton(L("Clear"), () => { publicKey.Text(""); privateKey.Text(""); symmetricKey.Text(""); });
    }
}
