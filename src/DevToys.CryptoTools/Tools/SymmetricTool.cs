using System.ComponentModel.Composition;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.UI;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tools;

[Export(typeof(IGuiTool))]
[Name("DevToys.CryptoTools.SymmetricTool")]
[ToolDisplayInformation(
    IconFontName = "FluentSystemIcons", IconGlyph = '\uE670',
    GroupName = CryptographyToolGroup.GroupName,
    ResourceManagerAssemblyIdentifier = nameof(CryptoToolsResourceAssemblyIdentifier),
    ResourceManagerBaseName = ResourceBaseName,
    ShortDisplayTitleResourceName = "SymTitle",
    LongDisplayTitleResourceName = "SymTitle",
    DescriptionResourceName = "SymDescription",
    AccessibleNameResourceName = "SymTitle")]
internal sealed class SymmetricTool : CryptoToolBase
{
    public SymmetricTool()
    {
        Note(L("SymNote"));
        var algorithm = Choice(L("Algorithm"), SymmetricCryptography.Algorithms);
        var key = Input(L("SymKey"));
        var input = Editor(L("Input"));
        var output = Editor(L("Output"), true);
        void Run(Func<string> action) { output.Text(""); output.Text(action()); }
        ActionButton(L("Encrypt"), () => Run(() => SymmetricCryptography.Encrypt(Selected(algorithm), key.Text ?? "", input.Text ?? "")));
        ActionButton(L("Decrypt"), () => Run(() => SymmetricCryptography.Decrypt(Selected(algorithm), key.Text ?? "", input.Text ?? "")));
        ActionButton(L("Clear"), () => { key.Text(""); input.Text(""); output.Text(""); });
    }
}
