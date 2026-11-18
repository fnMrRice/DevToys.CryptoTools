using System.Security.Cryptography;
using System.Text;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.Tools;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tests;

public class RsaToolTests
{
    private static readonly KeyMaterial Keys = KeyGenerator.Generate("RSA-2048");

    [Fact]
    public void FourModesControlSourcesPaddingAndSignatureInputs()
    {
        var tool = new RsaTool();
        Assert.True(tool.View.IsScrollable);
        Assert.Equal(UIOrientation.Vertical, Find<IUIStack>(tool, "rsa-configuration").Orientation);
        Assert.Equal(UIOrientation.Vertical, Find<IUISplitGrid>(tool, "rsa-editors").Orientation);
        Assert.Equal(4, Find<IUISelectDropDownList>(tool, "rsa-operation").Items!.Length);
        Assert.True(Find<IUISelectDropDownList>(tool, "rsa-encryption-padding").IsVisible);
        Assert.True(Find<IUISelectDropDownList>(tool, "rsa-public-source").IsVisible);
        Assert.False(Find<IUISelectDropDownList>(tool, "rsa-hash").IsVisible);
        Select(tool, "rsa-operation", "Sign");
        Assert.False(Find<IUISelectDropDownList>(tool, "rsa-public-source").IsVisible);
        Assert.True(Find<IUIGrid>(tool, "rsa-private").IsVisible);
        Assert.False(Find<IUISelectDropDownList>(tool, "rsa-encryption-padding").IsVisible);
        Assert.True(Find<IUISelectDropDownList>(tool, "rsa-signature-padding").IsVisible);
        Assert.True(Find<IUISelectDropDownList>(tool, "rsa-hash").IsVisible);
        Assert.False(Find<IUIMultiLineTextInput>(tool, "rsa-signature").IsVisible);
        Select(tool, "rsa-operation", "Verify");
        Assert.True(Find<IUISelectDropDownList>(tool, "rsa-public-source").IsVisible);
        Assert.True(Find<IUIMultiLineTextInput>(tool, "rsa-signature").IsVisible);
        Select(tool, "rsa-operation", "Decrypt");
        Assert.False(Find<IUISelectDropDownList>(tool, "rsa-public-source").IsVisible);
        Assert.False(Find<IUISelectDropDownList>(tool, "rsa-hash").IsVisible);
    }

    [Theory]
    [InlineData("OAEP-SHA256")]
    [InlineData("OAEP-SHA384")]
    [InlineData("OAEP-SHA512")]
    [InlineData("PKCS1")]
    public async Task EncryptionOutputCanBeTransferredToDecryption(string padding)
    {
        var tool = new RsaTool();
        Select(tool, "rsa-encryption-padding", padding);
        Find<IUIMultiLineTextInput>(tool, "rsa-public-pem").Text(Keys.PublicKey);
        Find<IUIMultiLineTextInput>(tool, "rsa-private-pem").Text(Keys.PrivateKey);
        Find<IUIMultiLineTextInput>(tool, "rsa-input").Text("hello 🔑");
        await Run(tool);
        Assert.NotEmpty(Find<IUIMultiLineTextInput>(tool, "rsa-output").Text);
        await Click(tool, "rsa-use-output");
        Assert.Equal("Decrypt", Find<IUISelectDropDownList>(tool, "rsa-operation").SelectedItem!.Value);
        await Run(tool);
        Assert.Equal("hello 🔑", Find<IUIMultiLineTextInput>(tool, "rsa-output").Text);
    }

    [Theory]
    [InlineData("SHA256", "PSS")]
    [InlineData("SHA384", "PSS")]
    [InlineData("SHA512", "PSS")]
    [InlineData("SHA256", "PKCS1")]
    [InlineData("SHA384", "PKCS1")]
    [InlineData("SHA512", "PKCS1")]
    public async Task SigningTransferPreservesMessageAndSignatureOptions(string hash, string padding)
    {
        var tool = new RsaTool();
        Select(tool, "rsa-operation", "Sign");
        Select(tool, "rsa-hash", hash);
        Select(tool, "rsa-signature-padding", padding);
        Find<IUIMultiLineTextInput>(tool, "rsa-private-pem").Text(Keys.PrivateKey);
        Find<IUIMultiLineTextInput>(tool, "rsa-public-pem").Text(Keys.PublicKey);
        Find<IUIMultiLineTextInput>(tool, "rsa-input").Text("message");
        await Run(tool);
        string signature = Find<IUIMultiLineTextInput>(tool, "rsa-output").Text;
        Assert.NotEmpty(signature);
        await Click(tool, "rsa-use-output");
        Assert.Equal("message", Find<IUIMultiLineTextInput>(tool, "rsa-input").Text);
        Assert.Equal(signature, Find<IUIMultiLineTextInput>(tool, "rsa-signature").Text);
        await Run(tool);
        Assert.Equal(Localization.Text.L("Valid"), Find<IUIMultiLineTextInput>(tool, "rsa-output").Text);
        Find<IUIMultiLineTextInput>(tool, "rsa-input").Text("changed");
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "rsa-output").Text);
        await Run(tool);
        Assert.Equal(Localization.Text.L("Invalid"), Find<IUIMultiLineTextInput>(tool, "rsa-output").Text);
    }

    [Theory]
    [InlineData(1, false)]
    [InlineData(2, false)]
    [InlineData(1, true)]
    [InlineData(2, true)]
    public async Task PublicKeyCanBeSuppliedAsEncodedDataOrModulusAndExponent(int encodingValue, bool parameters)
    {
        var tool = new RsaTool();
        Select(tool, "rsa-operation", "Verify");
        using var rsa = RSA.Create();
        rsa.ImportFromPem(Keys.PublicKey);
        if (parameters)
        {
            Select(tool, "rsa-public-source", "parameters");
            Select(tool, "rsa-parameter-encoding", (PublicKeyEncoding)encodingValue);
            var key = rsa.ExportParameters(false);
            Find<IUIMultiLineTextInput>(tool, "rsa-modulus").Text(Encode(key.Modulus!, encodingValue));
            Find<IUISingleLineTextInput>(tool, "rsa-exponent").Text(Encode(key.Exponent!, encodingValue));
        }
        else
        {
            Select(tool, "rsa-public-encoding", (PublicKeyEncoding)encodingValue);
            Find<IUIMultiLineTextInput>(tool, "rsa-public-pem").Text(Encode(rsa.ExportSubjectPublicKeyInfo(), encodingValue));
        }
        Find<IUIMultiLineTextInput>(tool, "rsa-input").Text("message");
        Find<IUIMultiLineTextInput>(tool, "rsa-signature").Text(RsaCryptography.Sign(Keys.PrivateKey, "message", "SHA256", "PSS"));
        await Run(tool);
        Assert.Equal(Localization.Text.L("Valid"), Find<IUIMultiLineTextInput>(tool, "rsa-output").Text);
    }

    [Fact]
    public async Task CertificateDropResetsEncodingAndExtractsRsaPublicKey()
    {
        var cert = CertificateGenerator.Generate(new CertificateOptions { PrivateKeyPem = Keys.PrivateKey });
        var tool = new RsaTool();
        Select(tool, "rsa-public-encoding", PublicKeyEncoding.Hex);
        await Drop(tool, "rsa-public-file", Encoding.UTF8.GetBytes(cert.Document));
        Assert.Equal(PublicKeyEncoding.Pem, Find<IUISelectDropDownList>(tool, "rsa-public-encoding").SelectedItem!.Value);
        Assert.Contains("BEGIN PUBLIC KEY", Find<IUIMultiLineTextInput>(tool, "rsa-public-pem").Text);
        Find<IUIMultiLineTextInput>(tool, "rsa-input").Text("certificate message");
        await Run(tool);
        string encrypted = Find<IUIMultiLineTextInput>(tool, "rsa-output").Text;
        Assert.Equal("certificate message", RsaCryptography.Decrypt(Keys.PrivateKey, encrypted, "OAEP-SHA256"));
        await Click(tool, "rsa-use-output");
        using var rsa = RSA.Create();
        rsa.ImportFromPem(Keys.PrivateKey);
        await Drop(tool, "rsa-private-file", rsa.ExportRSAPrivateKey());
        Assert.Contains("BEGIN PRIVATE KEY", Find<IUIMultiLineTextInput>(tool, "rsa-private-pem").Text);
        await Run(tool);
        Assert.Equal("certificate message", Find<IUIMultiLineTextInput>(tool, "rsa-output").Text);
    }

    [Fact]
    public async Task PrivateModesDoNotReadHiddenPublicMaterial()
    {
        var tool = new RsaTool();
        Find<IUIMultiLineTextInput>(tool, "rsa-public-pem").Text(Keys.PrivateKey);
        Select(tool, "rsa-operation", "Sign");
        Find<IUIMultiLineTextInput>(tool, "rsa-input").Text("message");
        await Run(tool);
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "rsa-output").Text);
    }

    private static string Encode(byte[] data, int format) => format == 1 ? Convert.ToBase64String(data) : Convert.ToHexString(data);
    private static T Find<T>(IGuiTool tool, string id) where T : IUIElement => Assert.IsAssignableFrom<T>(tool.View.GetChildElementById(id));
    private static void Select(IGuiTool tool, string id, object value)
    {
        var choice = Find<IUISelectDropDownList>(tool, id);
        choice.Select(choice.Items!.Single(item => Equals(item.Value, value)));
    }
    private static async Task Run(IGuiTool tool) => await Click(tool, "rsa-run");
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
