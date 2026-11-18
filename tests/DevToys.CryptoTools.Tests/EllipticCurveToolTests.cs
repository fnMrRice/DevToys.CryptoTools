using System.Text;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.Tools;
using Org.BouncyCastle.Crypto.Parameters;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tests;

public class EllipticCurveToolTests
{
    [Fact]
    public void Sm2UserIdIsOnlyShownForSm2AndCoordinatesAreNotOfferedForEdDsa()
    {
        var tool = new EllipticCurveSignatureTool();
        var id = Find<IUISingleLineTextInput>(tool, "ec-signature-sm2-id");
        Assert.False(id.IsVisible);
        Select(tool, "ec-signature-algorithm", "SM2");
        Assert.True(id.IsVisible);
        Select(tool, "ec-signature-key-source", "coordinates");
        Assert.True(Find<IUIStack>(tool, "ec-signature-coordinates").IsVisible);
        Assert.False(Find<IUIButton>(tool, "ec-signature-sign").IsEnabled);
        Select(tool, "ec-signature-algorithm", "Ed25519");
        Assert.False(id.IsVisible);
        Assert.Equal("key", Find<IUISelectDropDownList>(tool, "ec-signature-key-source").SelectedItem!.Value);
        Assert.True(Find<IUIButton>(tool, "ec-signature-sign").IsEnabled);
    }

    [Theory]
    [InlineData("SM2")]
    [InlineData("ECDSA-P256")]
    [InlineData("ECDSA-secp256k1")]
    [InlineData("ECDSA-brainpoolP384r1")]
    public async Task SignaturePageSignsAndVerifiesCoordinatePublicKeys(string algorithm)
    {
        var tool = new EllipticCurveSignatureTool();
        var key = KeyGenerator.Generate(algorithm);
        Select(tool, "ec-signature-algorithm", algorithm);
        Find<IUIMultiLineTextInput>(tool, "ec-signature-key-pem").Text(key.PrivateKey);
        Find<IUIMultiLineTextInput>(tool, "ec-signature-input").Text("hello 🔑");
        await Click(tool, "ec-signature-sign");
        Assert.NotEmpty(Find<IUIMultiLineTextInput>(tool, "ec-signature-signature").Text);
        var point = ((ECPublicKeyParameters)KeyGenerator.ReadKey(key.PublicKey, false)).Q.Normalize();
        Select(tool, "ec-signature-key-source", "coordinates");
        Find<IUISingleLineTextInput>(tool, "ec-signature-x").Text(point.AffineXCoord.ToBigInteger().ToString(16));
        Find<IUISingleLineTextInput>(tool, "ec-signature-y").Text(point.AffineYCoord.ToBigInteger().ToString(16));
        await Click(tool, "ec-signature-verify");
        Assert.Equal(Localization.Text.L("Valid"), Find<IUIMultiLineTextInput>(tool, "ec-signature-output").Text);
    }

    [Fact]
    public async Task EncryptionPageUsesDroppedCertificatePublicKeyAndMatchingPrivateKey()
    {
        var cert = CertificateGenerator.Generate("SM2", "CN=test", "", 30, false);
        var tool = new EllipticCurveTool();
        Select(tool, "ec-encryption-algorithm", "SM2-C1C3C2");
        await Drop(tool, "ec-encryption-key-file", Encoding.UTF8.GetBytes(cert.Document));
        Assert.Contains("BEGIN PUBLIC KEY", Find<IUIMultiLineTextInput>(tool, "ec-encryption-key-pem").Text);
        Find<IUIMultiLineTextInput>(tool, "ec-encryption-input").Text("message");
        await Click(tool, "ec-encryption-encrypt");
        await Click(tool, "ec-encryption-use-output");
        Find<IUIMultiLineTextInput>(tool, "ec-encryption-key-pem").Text(cert.PrivateKey);
        await Click(tool, "ec-encryption-decrypt");
        Assert.Equal("message", Find<IUIMultiLineTextInput>(tool, "ec-encryption-output").Text);
    }

    [Fact]
    public async Task InvalidDropClearsPreviousKeyInsteadOfSilentlyReusingIt()
    {
        var tool = new EllipticCurveTool();
        Find<IUIMultiLineTextInput>(tool, "ec-encryption-key-pem").Text(KeyGenerator.Generate("ECDH-P256").PublicKey);
        await Drop(tool, "ec-encryption-key-file", [1, 2, 3]);
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "ec-encryption-key-pem").Text);
    }

    private static T Find<T>(IGuiTool tool, string id) where T : IUIElement => Assert.IsAssignableFrom<T>(tool.View.GetChildElementById(id));
    private static void Select(IGuiTool tool, string id, object value)
    {
        var choice = Find<IUISelectDropDownList>(tool, id);
        choice.Select(choice.Items!.Single(item => Equals(item.Value, value)));
    }
    private static async Task Click(IGuiTool tool, string id) => await Find<IUIButton>(tool, id).OnClickAction!();
    private static async Task Drop(IGuiTool tool, string id, byte[] bytes)
    {
        string path = Path.GetTempFileName();
        try
        {
            await File.WriteAllBytesAsync(path, bytes);
            var file = SandboxedFileReader.FromFileInfo(new FileInfo(path));
            await Find<IUIFileSelector>(tool, id).OnFilesSelectedAction!([file]);
        }
        finally { File.Delete(path); }
    }
}
