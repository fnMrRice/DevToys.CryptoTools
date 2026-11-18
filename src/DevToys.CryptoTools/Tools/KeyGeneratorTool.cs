using System.ComponentModel.Composition;
using System.Globalization;
using System.Security.Cryptography;
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
    [Import(AllowDefault = true)]
    internal IFileStorage? FileStorage { get; set; }

    private readonly WorkflowContainer _workflow;
    protected override IUIElement BuildLayout() => _workflow.Root;

    public KeyGeneratorTool()
    {
        var algorithm = SelectDropDownList("key-algorithm")
            .WithItems(KeyGenerationOptions.Families.Select(a => Item(a, a)).ToArray()).Select(0);
        var rsaSize = SelectDropDownList("key-rsa-size")
            .WithItems(KeyGenerationOptions.RsaKeySizes.Select(size => Item(size.ToString(CultureInfo.InvariantCulture), size)).ToArray()).Select(0);
        var curve = SelectDropDownList("key-curve")
            .WithItems(KeyGenerationOptions.Curves.Select(name => Item(name, name)).ToArray()).Select(0);
        var rsaSizeSetting = Setting("key-rsa-size-setting").Title(L("KeyRsaSize"))
            .Icon("FluentSystemIcons", '\uF57D').InteractiveElement(rsaSize);
        var curveSetting = Setting("key-curve-setting").Title(L("KeyCurve"))
            .Icon("FluentSystemIcons", '\uE670').InteractiveElement(curve);
        var algorithmParameters = SettingGroup("key-algorithm-setting")
            .Title(L("Algorithm")).Description(L("KeyNote")).Icon("FluentSystemIcons", '\uE670')
            .InteractiveElement(algorithm);
        var fixedAlgorithm = Setting("key-algorithm-setting")
            .Title(L("Algorithm")).Description(L("KeyNote")).Icon("FluentSystemIcons", '\uE670')
            .InteractiveElement(algorithm);
        var configuration = Grid("key-configuration");
        var password = PasswordInput("key-password").HideCommandBar();
        var passwordSetting = Setting("key-password-setting")
            .Title(L("KeyPassword")).Description(L("KeyPasswordHint")).Icon("FluentSystemIcons", '\uE670')
            .InteractiveElement(password);
        var exportName = SingleLineTextInput("key-export-name").Text("keypair").HideCommandBar();
        var exportNameSetting = Setting("key-export-name-setting")
            .Title(L("KeyExportName")).Description(L("KeyExportNameDescription")).Icon("FluentSystemIcons", '\uE670')
            .InteractiveElement(exportName);
        var privateFormat = SelectDropDownList("key-private-format");
        var publicFormat = SelectDropDownList("key-public-format");
        var publicKey = MultiLineTextInput("key-public").Title(L("KeyPublicOutput")).ReadOnly().ShowCommandBar().Extendable().CommandBarExtraContent(publicFormat);
        var privateKey = MultiLineTextInput("key-private").Title(L("KeyPrivateOutput")).ReadOnly().ShowCommandBar().Extendable().CommandBarExtraContent(privateFormat);
        KeyPairDraft? draft = null;
        string? canonicalPrivateKey = null;
        string? canonicalPublicKey = null;
        bool updatingFormats = false;
        bool busy = false;
        var generate = Button("key-generate").Text(L("Generate")).AccentAppearance();
        var export = Button("key-export").Text(L("KeyExport"));
        var send = CreateActionButton(L("SendToCsr"), () =>
        {
            if (draft is null) throw new ArgumentException(L("NoSigningKey"));
            OpenRequest(draft);
        }, "key-send-csr");
        var clear = CreateActionButton(L("Clear"), () =>
        {
            draft = null;
            canonicalPrivateKey = null; canonicalPublicKey = null;
            publicKey.Text(""); privateKey.Text(""); password.Text("");
            RefreshFormats();
        }, "key-clear");
        generate.OnClick(() => ExecuteAsync(async () =>
        {
            if (busy) return;
            SetBusy(true);
            draft = null;
            canonicalPrivateKey = null; canonicalPublicKey = null;
            publicKey.Text(""); privateKey.Text("");
            try
            {
                string selectedAlgorithm = KeyGenerationOptions.Resolve(Selected(algorithm), (int)rsaSize.SelectedItem!.Value!, Selected(curve));
                string exportPassword = password.Text;
                var result = await Task.Run(() =>
                {
                    var keys = KeyGenerator.Generate(selectedAlgorithm);
                    return (Keys: keys, ExportedPrivateKey: PrivateKeyProtection.Export(keys.PrivateKey, exportPassword));
                });
                canonicalPublicKey = result.Keys.PublicKey;
                canonicalPrivateKey = result.ExportedPrivateKey;
                RefreshFormats();
                RefreshOutputs();
                // Direct CSR creation uses the generated key in memory, regardless
                // of whether its exported representation is password protected.
                draft = new KeyPairDraft(selectedAlgorithm, result.Keys.PublicKey, result.Keys.PrivateKey);
            }
            finally
            {
                SetBusy(false);
            }
        }));
        export.OnClick(() => ExecuteAsync(async () =>
        {
            if (busy) return;
            if (canonicalPrivateKey is null || canonicalPublicKey is null)
                throw new ArgumentException(L("KeyExportMissingKeys"));
            var storage = FileStorage ?? throw new NotSupportedException(L("KeyExportUnavailable"));
            SetBusy(true);
            byte[] privateBytes = [];
            try
            {
                string baseName = exportName.Text;
                string privateKeyPem = canonicalPrivateKey;
                string publicKeyPem = canonicalPublicKey;
                var selectedPrivateFormat = (KeyOutputFormat)privateFormat.SelectedItem!.Value!;
                var selectedPublicFormat = (KeyOutputFormat)publicFormat.SelectedItem!.Value!;
                string? directory = await storage.PickFolderAsync();
                if (string.IsNullOrWhiteSpace(directory)) return;
                privateBytes = KeyOutputFormatter.ExportPrivate(privateKeyPem, selectedPrivateFormat);
                byte[] publicBytes = KeyOutputFormatter.ExportPublic(publicKeyPem, selectedPublicFormat);
                await KeyPairFileExport.ExportAsync(directory, baseName, privateBytes.AsMemory(), publicBytes.AsMemory());
            }
            finally { CryptographicOperations.ZeroMemory(privateBytes); SetBusy(false); }
        }));
        void SetBusy(bool value)
        {
            busy = value;
            foreach (var control in new IUIElement[] { generate, export, send, clear, algorithm, rsaSize, curve, password, exportName, privateFormat, publicFormat })
                if (value) control.Disable(); else control.Enable();
        }
        void RefreshAlgorithmParameters()
        {
            string family = Selected(algorithm);
            IUIElement card;
            if (family is "RSA" or "ECDSA" or "ECDH")
            {
                algorithmParameters.WithSettings(family == "RSA" ? rsaSizeSetting : curveSetting);
                card = algorithmParameters;
            }
            else card = fixedAlgorithm;
            configuration.Cells(Cell().WithChild(card));
        }
        void RefreshFormats()
        {
            updatingFormats = true;
            try
            {
                var selectedPrivateFormat = privateFormat.SelectedItem?.Value as KeyOutputFormat? ?? KeyOutputFormat.Pkcs8Pem;
                var selectedPublicFormat = publicFormat.SelectedItem?.Value as KeyOutputFormat? ?? KeyOutputFormat.Pem;
                var privateItems = new List<IUIDropDownListItem> { Item("PKCS#8 (PEM)", KeyOutputFormat.Pkcs8Pem) };
                if (canonicalPrivateKey is not null && KeyOutputFormatter.CanUseTraditionalPrivatePem(canonicalPrivateKey))
                    privateItems.Add(Item("PEM (PKCS#1 / SEC1)", KeyOutputFormat.TraditionalPem));
                privateItems.AddRange([Item("DER (Hex)", KeyOutputFormat.DerHex), Item("DER (Base64)", KeyOutputFormat.DerBase64)]);
                privateFormat.WithItems([.. privateItems]).Select(privateItems.FirstOrDefault(item => Equals(item.Value, selectedPrivateFormat)) ?? privateItems[0]);
                var publicItems = new List<IUIDropDownListItem> { Item("PEM (SPKI)", KeyOutputFormat.Pem) };
                if (canonicalPublicKey is not null && KeyOutputFormatter.CanUseTraditionalPublicPem(canonicalPublicKey))
                    publicItems.Add(Item("PEM (PKCS#1)", KeyOutputFormat.TraditionalPem));
                publicItems.AddRange([Item("DER (Hex)", KeyOutputFormat.DerHex), Item("DER (Base64)", KeyOutputFormat.DerBase64)]);
                publicFormat.WithItems([.. publicItems]).Select(publicItems.FirstOrDefault(item => Equals(item.Value, selectedPublicFormat)) ?? publicItems[0]);
            }
            finally { updatingFormats = false; }
        }
        void RefreshOutputs()
        {
            if (canonicalPrivateKey is not null)
                privateKey.Text(KeyOutputFormatter.FormatPrivate(canonicalPrivateKey, (KeyOutputFormat)privateFormat.SelectedItem!.Value!));
            if (canonicalPublicKey is not null)
                publicKey.Text(KeyOutputFormatter.FormatPublic(canonicalPublicKey, (KeyOutputFormat)publicFormat.SelectedItem!.Value!));
        }
        algorithm.OnItemSelected(_ => RefreshAlgorithmParameters());
        privateFormat.OnItemSelected(_ => { if (!updatingFormats) Execute(RefreshOutputs); });
        publicFormat.OnItemSelected(_ => { if (!updatingFormats) Execute(RefreshOutputs); });
        RefreshAlgorithmParameters();
        RefreshFormats();
        var actions = Stack("key-actions").Horizontal().SmallSpacing()
            .AlignHorizontally(UIHorizontalAlignment.Left).WithChildren(generate, export, send, clear);
        var editors = SplitGrid("key-editors").Vertical().WithLeftPaneChild(privateKey).WithRightPaneChild(publicKey);
        var configurationRows = Stack().Vertical().SmallSpacing().WithChildren(configuration, passwordSetting, exportNameSetting);
        var layout = Grid("key-layout").Rows(Auto, Auto, Fraction(1), Auto).RowLargeSpacing().Cells(
            Cell().Row(0).WithChild(configurationRows), Cell().Row(1).WithChild(actions),
            Cell().Row(2).WithChild(editors), Cell().Row(3).WithChild(Status));
        _workflow = new WorkflowContainer(layout);
    }

    private void OpenRequest(KeyPairDraft draft) => _workflow.Open(L("CsrTitle"), new CertificateRequestTool(), DraftTransfer.KeyPairDataType, draft);
}
