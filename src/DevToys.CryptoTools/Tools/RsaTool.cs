using System.ComponentModel.Composition;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.UI;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tools;

[Export(typeof(IGuiTool))]
[Name("DevToys.CryptoTools.RsaTool")]
[ToolDisplayInformation(
    IconFontName = "FluentSystemIcons", IconGlyph = '\uE670',
    GroupName = CryptographyToolGroup.GroupName,
    ResourceManagerAssemblyIdentifier = nameof(CryptoToolsResourceAssemblyIdentifier),
    ResourceManagerBaseName = ResourceBaseName,
    ShortDisplayTitleResourceName = "RsaTitle",
    LongDisplayTitleResourceName = "RsaTitle",
    DescriptionResourceName = "RsaDescription",
    AccessibleNameResourceName = "RsaTitle")]
internal sealed class RsaTool : CryptoToolBase
{
    public RsaTool()
    {
        Note(L("RsaNote"));
        var padding = Choice(L("Padding"), RsaCryptography.EncryptionPaddings);
        var hash = Choice(L("Hash"), RsaCryptography.Hashes);
        var signaturePadding = Choice(L("SignaturePadding"), RsaCryptography.SignaturePaddings);
        var key = Editor(L("KeyPem"));
        var input = Editor(L("Input"));
        var signature = Editor(L("Signature"));
        var output = Editor(L("Output"), true);
        void Run(Func<string> action) { output.Text(""); output.Text(action()); }
        ActionButton(L("Encrypt"), () => Run(() => RsaCryptography.Encrypt(key.Text ?? "", input.Text ?? "", Selected(padding))));
        ActionButton(L("Decrypt"), () => Run(() => RsaCryptography.Decrypt(key.Text ?? "", input.Text ?? "", Selected(padding))));
        ActionButton(L("Sign"), () => Run(() => RsaCryptography.Sign(key.Text ?? "", input.Text ?? "", Selected(hash), Selected(signaturePadding))));
        ActionButton(L("Verify"), () => Run(() => L(RsaCryptography.Verify(key.Text ?? "", input.Text ?? "", signature.Text ?? "", Selected(hash), Selected(signaturePadding)) ? "Valid" : "Invalid")));
        ActionButton(L("Clear"), () => { key.Text(""); input.Text(""); signature.Text(""); output.Text(""); });
    }
}
