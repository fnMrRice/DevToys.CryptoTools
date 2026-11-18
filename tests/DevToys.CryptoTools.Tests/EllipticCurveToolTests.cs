using System.Text;
using System.Security.Cryptography;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.Tools;
using Org.BouncyCastle.Crypto.Parameters;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tests;

public class EllipticCurveToolTests
{
    [Fact]
    public void ModesControlPublicSourcePrivateKeyAndSm2UserId()
    {
        var tool = new EllipticCurveTool();
        Assert.Equal(4, Find<IUISelectDropDownList>(tool, "ec-operation").Items!.Length);
        Assert.True(Find<IUISelectDropDownList>(tool, "ec-public-source").IsVisible);
        var source = Find<IUISelectDropDownList>(tool, "ec-public-source");
        Assert.Same(source, Find<IUISetting>(tool, "ec-public-source-setting").InteractiveElement);
        Assert.DoesNotContain(source, Find<IUIStack>(tool, "ec-public-panel").Children!);
        Assert.False(Find<IUISingleLineTextInput>(tool, "ec-sm2-id").IsVisible);
        Select(tool, "ec-operation", "Sign");
        Select(tool, "ec-algorithm", "SM2");
        Assert.True(Find<IUISingleLineTextInput>(tool, "ec-sm2-id").IsVisible);
        Assert.False(Find<IUISelectDropDownList>(tool, "ec-public-source").IsVisible);
        Assert.True(Find<IUIGrid>(tool, "ec-private").IsVisible);
        Select(tool, "ec-operation", "Verify");
        Assert.True(Find<IUISelectDropDownList>(tool, "ec-public-source").IsVisible);
        Assert.True(Find<IUISingleLineTextInput>(tool, "ec-sm2-id").IsVisible);
        Assert.True(Find<IUIMultiLineTextInput>(tool, "ec-signature").IsVisible);
        Select(tool, "ec-operation", "Encrypt");
        Assert.False(Find<IUISingleLineTextInput>(tool, "ec-sm2-id").IsVisible);
        Assert.False(Find<IUIMultiLineTextInput>(tool, "ec-signature").IsVisible);
        Select(tool, "ec-operation", "Decrypt");
        Assert.False(Find<IUISelectDropDownList>(tool, "ec-public-source").IsVisible);
        Assert.False(Find<IUISingleLineTextInput>(tool, "ec-sm2-id").IsVisible);
    }

    [Fact]
    public void ModeSwitchesPreserveCurveAndHideUnsupportedCoordinates()
    {
        var tool = new EllipticCurveTool();
        Select(tool, "ec-algorithm", "ECDH-brainpoolP384r1");
        Select(tool, "ec-public-source", "coordinates");
        Select(tool, "ec-operation", "Sign");
        Assert.Equal("ECDSA-brainpoolP384r1", Selected(tool, "ec-algorithm"));
        Select(tool, "ec-operation", "Verify");
        Assert.True(Find<IUIStack>(tool, "ec-coordinates").IsVisible);
        Select(tool, "ec-algorithm", "Ed25519");
        Assert.Equal("key", Selected(tool, "ec-public-source"));
        Assert.DoesNotContain(Find<IUISelectDropDownList>(tool, "ec-public-source").Items!, item => Equals(item.Value, "coordinates"));
        Select(tool, "ec-operation", "Encrypt");
        Assert.Equal("ECDH-brainpoolP384r1", Selected(tool, "ec-algorithm"));
        Select(tool, "ec-algorithm", "X25519");
        Assert.DoesNotContain(Find<IUISelectDropDownList>(tool, "ec-public-source").Items!, item => Equals(item.Value, "coordinates"));
    }

    [Theory]
    [InlineData("SM2")]
    [InlineData("ECDSA-P256")]
    [InlineData("ECDSA-secp256k1")]
    [InlineData("Ed25519")]
    public async Task SignOutputTransfersToVerifyWhileKeepingOriginalMessage(string algorithm)
    {
        var tool = new EllipticCurveTool();
        var key = KeyGenerator.Generate(algorithm);
        Select(tool, "ec-operation", "Sign");
        Select(tool, "ec-algorithm", algorithm);
        Find<IUIMultiLineTextInput>(tool, "ec-private-pem").Text(key.PrivateKey);
        Find<IUIMultiLineTextInput>(tool, "ec-public-pem").Text(key.PublicKey);
        Find<IUIMultiLineTextInput>(tool, "ec-input").Text("hello 🔑");
        await Run(tool);
        string signature = Find<IUIMultiLineTextInput>(tool, "ec-output").Text;
        Assert.NotEmpty(signature);
        await Click(tool, "ec-use-output");
        Assert.Equal("Verify", Selected(tool, "ec-operation"));
        Assert.Equal("hello 🔑", Find<IUIMultiLineTextInput>(tool, "ec-input").Text);
        Assert.Equal(signature, Find<IUIMultiLineTextInput>(tool, "ec-signature").Text);
        await Run(tool);
        Assert.Equal(Localization.Text.L("Valid"), Find<IUIMultiLineTextInput>(tool, "ec-output").Text);
        Find<IUIMultiLineTextInput>(tool, "ec-input").Text("modified");
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "ec-output").Text);
        await Run(tool);
        Assert.Equal(Localization.Text.L("Invalid"), Find<IUIMultiLineTextInput>(tool, "ec-output").Text);
    }

    [Theory]
    [InlineData("SM2", 1)]
    [InlineData("SM2", 2)]
    [InlineData("Ed448", 1)]
    [InlineData("ECDSA-secp256k1", 2)]
    public async Task VerificationAcceptsBase64AndHexSpki(string algorithm, int format)
    {
        var tool = new EllipticCurveTool();
        var key = KeyGenerator.Generate(algorithm);
        Select(tool, "ec-operation", "Verify");
        Select(tool, "ec-algorithm", algorithm);
        Select(tool, "ec-public-encoding", (PublicKeyEncoding)format);
        byte[] der = Convert.FromBase64String(key.PublicKey[PemEncoding.Find(key.PublicKey).Base64Data]);
        Find<IUIMultiLineTextInput>(tool, "ec-public-pem").Text(format == 1 ? Convert.ToBase64String(der) : Convert.ToHexString(der));
        Find<IUIMultiLineTextInput>(tool, "ec-input").Text("message");
        Find<IUIMultiLineTextInput>(tool, "ec-signature").Text(EllipticCurveCryptography.Sign(algorithm, key.PrivateKey, "message"));
        await Run(tool);
        Assert.Equal(Localization.Text.L("Valid"), Find<IUIMultiLineTextInput>(tool, "ec-output").Text);
    }

    [Theory]
    [InlineData("SM2", 1)]
    [InlineData("ECDSA-P384", 2)]
    public async Task VerificationAcceptsCoordinateEncodings(string algorithm, int format)
    {
        var tool = new EllipticCurveTool();
        var key = KeyGenerator.Generate(algorithm);
        Select(tool, "ec-operation", "Verify");
        Select(tool, "ec-algorithm", algorithm);
        SetCoordinates(tool, algorithm, key.PublicKey, (PublicKeyEncoding)format);
        Find<IUIMultiLineTextInput>(tool, "ec-input").Text("message");
        Find<IUIMultiLineTextInput>(tool, "ec-signature").Text(EllipticCurveCryptography.Sign(algorithm, key.PrivateKey, "message"));
        await Run(tool);
        Assert.Equal(Localization.Text.L("Valid"), Find<IUIMultiLineTextInput>(tool, "ec-output").Text);
    }

    [Fact]
    public async Task EncryptionAcceptsPublicCoordinates()
    {
        var tool = new EllipticCurveTool();
        var key = KeyGenerator.Generate("ECDH-P384");
        Select(tool, "ec-algorithm", "ECDH-P384");
        SetCoordinates(tool, "ECDH-P384", key.PublicKey, PublicKeyEncoding.Base64);
        Find<IUIMultiLineTextInput>(tool, "ec-input").Text("coordinate message");
        await Run(tool);
        string encrypted = Find<IUIMultiLineTextInput>(tool, "ec-output").Text;
        Assert.Equal("coordinate message", EllipticCurveCryptography.Decrypt("ECDH-P384", key.PrivateKey, encrypted));
    }

    [Fact]
    public async Task DroppedCertificateResetsPublicEncodingAndExtractsPublicKey()
    {
        var cert = CertificateGenerator.Generate("SM2", "CN=test", "", 30, false);
        var tool = new EllipticCurveTool();
        Select(tool, "ec-algorithm", "SM2-C1C2C3");
        Select(tool, "ec-public-encoding", PublicKeyEncoding.Hex);
        await Drop(tool, Encoding.UTF8.GetBytes(cert.Document));
        Assert.Equal(PublicKeyEncoding.Pem, Selected(tool, "ec-public-encoding"));
        Assert.Contains("BEGIN PUBLIC KEY", Find<IUIMultiLineTextInput>(tool, "ec-public-pem").Text);
        Find<IUIMultiLineTextInput>(tool, "ec-input").Text("message");
        await Run(tool);
        await Click(tool, "ec-use-output");
        Assert.Equal("Decrypt", Selected(tool, "ec-operation"));
        Find<IUIMultiLineTextInput>(tool, "ec-private-pem").Text(cert.PrivateKey);
        await Run(tool);
        Assert.Equal("message", Find<IUIMultiLineTextInput>(tool, "ec-output").Text);
        Select(tool, "ec-operation", "Sign");
        Assert.Equal("SM2", Selected(tool, "ec-algorithm"));
        Select(tool, "ec-operation", "Encrypt");
        Assert.Equal("SM2-C1C2C3", Selected(tool, "ec-algorithm"));
    }

    [Fact]
    public async Task PrivateOperationsNeverUseTheHiddenPublicKey()
    {
        var tool = new EllipticCurveTool();
        Select(tool, "ec-operation", "Sign");
        var key = KeyGenerator.Generate("ECDSA-P256");
        Find<IUIMultiLineTextInput>(tool, "ec-public-pem").Text(key.PrivateKey);
        Find<IUIMultiLineTextInput>(tool, "ec-input").Text("message");
        await Run(tool);
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "ec-output").Text);
    }

    [Fact]
    public async Task InvalidDropClearsPreviousPublicKey()
    {
        var tool = new EllipticCurveTool();
        Find<IUIMultiLineTextInput>(tool, "ec-public-pem").Text(KeyGenerator.Generate("ECDH-P256").PublicKey);
        await Drop(tool, [1, 2, 3]);
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "ec-public-pem").Text);
    }

    private static void SetCoordinates(EllipticCurveTool tool, string algorithm, string pem, PublicKeyEncoding format)
    {
        var point = ((ECPublicKeyParameters)KeyGenerator.ReadKey(pem, false)).Q.Normalize();
        Select(tool, "ec-public-source", "coordinates");
        Select(tool, "ec-coordinate-encoding", format);
        byte[] x = point.AffineXCoord.ToBigInteger().ToByteArrayUnsigned();
        byte[] y = point.AffineYCoord.ToBigInteger().ToByteArrayUnsigned();
        Find<IUISingleLineTextInput>(tool, "ec-x").Text(format == PublicKeyEncoding.Hex ? Convert.ToHexString(x) : Convert.ToBase64String(x));
        Find<IUISingleLineTextInput>(tool, "ec-y").Text(format == PublicKeyEncoding.Hex ? Convert.ToHexString(y) : Convert.ToBase64String(y));
    }

    private static T Find<T>(IGuiTool tool, string id) where T : IUIElement => Assert.IsAssignableFrom<T>(tool.View.GetChildElementById(id));
    private static object Selected(IGuiTool tool, string id) => Find<IUISelectDropDownList>(tool, id).SelectedItem!.Value!;
    private static void Select(IGuiTool tool, string id, object value)
    {
        var choice = Find<IUISelectDropDownList>(tool, id);
        choice.Select(choice.Items!.Single(item => Equals(item.Value, value)));
    }
    private static async Task Run(IGuiTool tool) => await Click(tool, "ec-run");
    private static async Task Click(IGuiTool tool, string id) => await Find<IUIButton>(tool, id).OnClickAction!();
    private static async Task Drop(IGuiTool tool, byte[] bytes)
    {
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(path, bytes);
            var file = SandboxedFileReader.FromFileInfo(new FileInfo(path));
            await Find<IUIFileSelector>(tool, "ec-public-file").OnFilesSelectedAction!([file]);
        }
        finally { File.Delete(path); }
    }
}
