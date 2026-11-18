using System.ComponentModel.Composition;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.UI;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tools;

[Export(typeof(IGuiTool))]
[Name("DevToys.CryptoTools.EllipticCurveTool")]
[ToolDisplayInformation(
    IconFontName = "FluentSystemIcons", IconGlyph = '\uE8C9',
    GroupName = CryptographyToolGroup.GroupName,
    ResourceManagerAssemblyIdentifier = nameof(CryptoToolsResourceAssemblyIdentifier),
    ResourceManagerBaseName = ResourceBaseName,
    ShortDisplayTitleResourceName = "EcEncryptionTitle",
    LongDisplayTitleResourceName = "EcEncryptionTitle",
    DescriptionResourceName = "EcEncryptionDescription",
    AccessibleNameResourceName = "EcEncryptionTitle")]
internal sealed class EllipticCurveTool : EllipticCurvePageBase
{
    public EllipticCurveTool() : base("ec-encryption", EllipticCurveCryptography.EncryptionAlgorithms)
    {
        var sm2Hint = Label().Text(L("EcSm2EncryptHint")).AlignHorizontally(UIHorizontalAlignment.Left).Hide();
        Algorithm.OnItemSelected(_ =>
        {
            if (Selected(Algorithm).StartsWith("SM2-", StringComparison.Ordinal)) sm2Hint.Show(); else sm2Hint.Hide();
            OutputText.Text("");
        });
        var options = Stack().Vertical().MediumSpacing().WithChildren(Algorithm,
            Label().Text(L("EcEncryptHint")).AlignHorizontally(UIHorizontalAlignment.Left), sm2Hint);
        SetLayout("ec-encryption", options, KeyInput.View, InputText,
            CreateActionButton(L("Encrypt"), () => ShowResult(() => EllipticCurveCryptography.Encrypt(Selected(Algorithm), KeyInput.GetPem(), InputText.Text)), "ec-encryption-encrypt").AccentAppearance(),
            CreateActionButton(L("Decrypt"), () => ShowResult(() => EllipticCurveCryptography.Decrypt(Selected(Algorithm), KeyInput.GetPem(), InputText.Text)), "ec-encryption-decrypt"),
            CreateActionButton(L("UseOutputAsInput"), () => { InputText.Text(OutputText.Text); OutputText.Text(""); }, "ec-encryption-use-output"),
            CreateActionButton(L("Clear"), () => { KeyInput.Clear(); InputText.Text(""); OutputText.Text(""); }, "ec-encryption-clear"));
    }
}
