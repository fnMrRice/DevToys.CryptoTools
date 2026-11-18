using System.ComponentModel.Composition;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.UI;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tools;

[Export(typeof(IGuiTool))]
[Name("DevToys.CryptoTools.CertificateGeneratorTool")]
[ToolDisplayInformation(
    IconFontName = "FluentSystemIcons", IconGlyph = '\uE670',
    GroupName = PredefinedCommonToolGroupNames.Generators,
    ResourceManagerAssemblyIdentifier = nameof(CryptoToolsResourceAssemblyIdentifier),
    ResourceManagerBaseName = ResourceBaseName,
    ShortDisplayTitleResourceName = "CertTitle",
    LongDisplayTitleResourceName = "CertTitle",
    DescriptionResourceName = "CertDescription",
    AccessibleNameResourceName = "CertTitle")]
internal sealed class CertificateGeneratorTool : CryptoToolBase
{
    public CertificateGeneratorTool()
    {
        Note(L("CertNote"));
        var algorithm = Choice(L("Algorithm"), CertificateGenerator.Algorithms);
        var subject = Input(L("Subject"), "CN=localhost");
        var dns = Input(L("DnsNames"), "localhost");
        var days = Input(L("Validity"), "365");
        var output = Editor(L("Output"), true);
        var privateKey = Editor(L("PrivateKey"), true);
        void Generate(bool csr)
        {
            output.Text(""); privateKey.Text("");
            if (!int.TryParse(days.Text, out int validity)) throw new ArgumentException(L("InvalidValidity"));
            var result = CertificateGenerator.Generate(Selected(algorithm), subject.Text ?? "", dns.Text ?? "", validity, csr);
            output.Text(result.Document);
            privateKey.Text(result.PrivateKey);
        }
        ActionButton(L("GenerateCert"), () => Generate(false));
        ActionButton(L("GenerateCsr"), () => Generate(true));
        ActionButton(L("Clear"), () => { output.Text(""); privateKey.Text(""); });
    }
}
