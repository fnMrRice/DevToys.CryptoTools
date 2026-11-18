using System.ComponentModel.Composition;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.UI;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tools;

[Export(typeof(IGuiTool))]
[Name("DevToys.CryptoTools.EllipticCurveTool")]
[ToolDisplayInformation(
    IconFontName = "FluentSystemIcons", IconGlyph = '\uE670',
    GroupName = CryptographyToolGroup.GroupName,
    ResourceManagerAssemblyIdentifier = nameof(CryptoToolsResourceAssemblyIdentifier),
    ResourceManagerBaseName = ResourceBaseName,
    ShortDisplayTitleResourceName = "EcTitle",
    LongDisplayTitleResourceName = "EcTitle",
    DescriptionResourceName = "EcDescription",
    AccessibleNameResourceName = "EcTitle")]
internal sealed class EllipticCurveTool : CryptoToolBase
{
    public EllipticCurveTool()
    {
        Note(L("EcNote"));
        Note(L("EcKeyNote"));
        Note(L("Sm2Note"));
        var signing = Choice(L("SigningAlgorithm"), EllipticCurveCryptography.SigningAlgorithms);
        var encryption = Choice(L("EncryptionAlgorithm"), EllipticCurveCryptography.EncryptionAlgorithms);
        var sm2Id = Input(L("Sm2Id"), "1234567812345678");
        var key = Editor(L("KeyPem"));
        var input = Editor(L("Input"));
        var signature = Editor(L("Signature"));
        var output = Editor(L("Output"), true);
        void Run(Func<string> action) { output.Text(""); output.Text(action()); }
        ActionButton(L("Encrypt"), () => Run(() => EllipticCurveCryptography.Encrypt(Selected(encryption), key.Text ?? "", input.Text ?? "")));
        ActionButton(L("Decrypt"), () => Run(() => EllipticCurveCryptography.Decrypt(Selected(encryption), key.Text ?? "", input.Text ?? "")));
        ActionButton(L("Sign"), () => Run(() => EllipticCurveCryptography.Sign(Selected(signing), key.Text ?? "", input.Text ?? "", sm2Id.Text ?? "")));
        ActionButton(L("Verify"), () => Run(() => L(EllipticCurveCryptography.Verify(Selected(signing), key.Text ?? "", input.Text ?? "", signature.Text ?? "", sm2Id.Text ?? "") ? "Valid" : "Invalid")));
        ActionButton(L("Clear"), () => { key.Text(""); input.Text(""); signature.Text(""); output.Text(""); });
    }
}
