using System.ComponentModel.Composition;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.UI;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tools;

[Export(typeof(IGuiTool))]
[Name("DevToys.CryptoTools.EllipticCurveSignatureTool")]
[ToolDisplayInformation(
    IconFontName = "FluentSystemIcons", IconGlyph = '\uE8C9',
    GroupName = CryptographyToolGroup.GroupName,
    ResourceManagerAssemblyIdentifier = nameof(CryptoToolsResourceAssemblyIdentifier),
    ResourceManagerBaseName = ResourceBaseName,
    ShortDisplayTitleResourceName = "EcSignatureTitle",
    LongDisplayTitleResourceName = "EcSignatureTitle",
    DescriptionResourceName = "EcSignatureDescription",
    AccessibleNameResourceName = "EcSignatureTitle")]
internal sealed class EllipticCurveSignatureTool : EllipticCurvePageBase
{
    private readonly IUISingleLineTextInput _sm2Id = SingleLineTextInput("ec-signature-sm2-id").Title(L("Sm2Id")).Text("1234567812345678").Hide();
    private readonly IUISelectDropDownList _keySource = SelectDropDownList("ec-signature-key-source").Title(L("VerificationKeySource"))
        .WithItems(Item(L("KeyFileSource"), "key"), Item(L("CoordinateSource"), "coordinates")).Select(0).AlignHorizontally(UIHorizontalAlignment.Left);
    private readonly IUISingleLineTextInput _x = SingleLineTextInput("ec-signature-x").Title(L("CoordinateX")).ShowCommandBar();
    private readonly IUISingleLineTextInput _y = SingleLineTextInput("ec-signature-y").Title(L("CoordinateY")).ShowCommandBar();
    private readonly IUIMultiLineTextInput _signature = MultiLineTextInput("ec-signature-signature").Title(L("Signature")).ShowCommandBar().CanCopyWhenEditable();
    private readonly IUIElement _coordinates;
    private readonly IUIButton _sign;

    public EllipticCurveSignatureTool() : base("ec-signature", EllipticCurveCryptography.SigningAlgorithms)
    {
        _coordinates = Stack("ec-signature-coordinates").Vertical().MediumSpacing().WithChildren(_x, _y,
            Label().Text(L("CoordinateHint")).AlignHorizontally(UIHorizontalAlignment.Left)).Hide();
        _sign = CreateActionButton(L("Sign"), () => ShowResult(() =>
        {
            string signature = EllipticCurveCryptography.Sign(Selected(Algorithm), KeyInput.GetPem(), InputText.Text, _sm2Id.Text);
            _signature.Text(signature);
            return signature;
        }), "ec-signature-sign").AccentAppearance();
        Algorithm.OnItemSelected(_ => UpdateAlgorithm());
        _keySource.OnItemSelected(_ => UpdateKeySource());
        var options = Stack().Vertical().MediumSpacing().WithChildren(Algorithm, _keySource, _sm2Id,
            Label().Text(L("EcSignHint")).AlignHorizontally(UIHorizontalAlignment.Left));
        var keyPanel = Grid("ec-signature-key-panel").Cells(At(0, 0, KeyInput.View), At(0, 0, _coordinates));
        var inputPane = Grid().Rows(Fraction(2), Fraction(1)).RowMediumSpacing().Cells(At(0, 0, InputText), At(1, 0, _signature));
        SetLayout("ec-signature", options, keyPanel, inputPane, _sign,
            CreateActionButton(L("Verify"), () => ShowResult(() =>
            {
                string key = Selected(_keySource) == "coordinates"
                    ? EllipticCurveKeyImport.FromCoordinates(Selected(Algorithm), _x.Text, _y.Text) : KeyInput.GetPem();
                return L(EllipticCurveCryptography.Verify(Selected(Algorithm), key, InputText.Text, _signature.Text, _sm2Id.Text) ? "Valid" : "Invalid");
            }), "ec-signature-verify"),
            CreateActionButton(L("Clear"), () => { KeyInput.Clear(); _x.Text(""); _y.Text(""); InputText.Text(""); _signature.Text(""); OutputText.Text(""); }, "ec-signature-clear"));
        UpdateAlgorithm();
    }

    private void UpdateAlgorithm()
    {
        if (Selected(Algorithm) == "SM2") _sm2Id.Show(); else _sm2Id.Hide();
        string previous = Selected(_keySource);
        _keySource.WithItems(EcDomains.SupportsCoordinates(Selected(Algorithm))
            ? [Item(L("KeyFileSource"), "key"), Item(L("CoordinateSource"), "coordinates")]
            : [Item(L("KeyFileSource"), "key")]).Select(0);
        if (previous == "coordinates" && EcDomains.SupportsCoordinates(Selected(Algorithm))) _keySource.Select(1);
        UpdateKeySource();
    }

    private void UpdateKeySource()
    {
        bool coordinates = Selected(_keySource) == "coordinates";
        if (coordinates) { KeyInput.View.Hide(); _coordinates.Show(); _sign.Disable(); }
        else { KeyInput.View.Show(); _coordinates.Hide(); _sign.Enable(); }
        OutputText.Text("");
    }
}
