using System.Security.Cryptography;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.Tools;
using Org.BouncyCastle.Crypto.Parameters;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tests;

public class KeyGeneratorOutputUiTests
{
    [Theory]
    [InlineData("RSA", 3072, "P256", "RSA-3072")]
    [InlineData("ECDSA", 2048, "secp256k1", "ECDSA-secp256k1")]
    [InlineData("ECDH", 2048, "brainpoolP512r1", "ECDH-brainpoolP512r1")]
    public async Task FamilyParametersControlTheGeneratedKey(string family, int bits, string curve, string expectedAlgorithm)
    {
        var tool = new KeyGeneratorTool();
        Select(tool, "key-algorithm", family);
        Select(tool, family == "RSA" ? "key-rsa-size" : "key-curve", family == "RSA" ? bits : curve);
        await Click(tool, "key-generate");
        string privateKey = Find<IUIMultiLineTextInput>(tool, "key-private").Text;
        if (family == "RSA")
        {
            using var rsa = RSA.Create();
            rsa.ImportFromPem(privateKey);
            Assert.Equal(bits, rsa.KeySize);
        }
        else
        {
            var key = Assert.IsAssignableFrom<ECPrivateKeyParameters>(KeyGenerator.ReadKey(privateKey, true));
            var expectedDomain = EcDomains.ForAlgorithm(expectedAlgorithm);
            Assert.Equal(expectedDomain.Curve, key.Parameters.Curve);
            Assert.Equal(expectedDomain.G, key.Parameters.G);
            if (family == "ECDSA")
            {
                await Click(tool, "key-send-csr");
                Assert.Equal(expectedAlgorithm, Find<IUISelectDropDownList>(tool, "csr-algorithm").SelectedItem!.Value);
            }
        }
    }

    [Fact]
    public async Task SwitchingOutputFormatsPreservesTheGeneratedKeyPair()
    {
        var tool = new KeyGeneratorTool();
        await Click(tool, "key-generate");
        string privatePem = Find<IUIMultiLineTextInput>(tool, "key-private").Text;
        string publicPem = Find<IUIMultiLineTextInput>(tool, "key-public").Text;
        Select(tool, "key-private-format", KeyOutputFormat.TraditionalPem);
        Select(tool, "key-public-format", KeyOutputFormat.TraditionalPem);
        Assert.StartsWith("-----BEGIN RSA PRIVATE KEY-----", Find<IUIMultiLineTextInput>(tool, "key-private").Text);
        Assert.StartsWith("-----BEGIN RSA PUBLIC KEY-----", Find<IUIMultiLineTextInput>(tool, "key-public").Text);
        using var converted = RSA.Create();
        converted.ImportFromPem(Find<IUIMultiLineTextInput>(tool, "key-private").Text);
        Assert.Equal(publicPem, converted.ExportSubjectPublicKeyInfoPem());
        Select(tool, "key-private-format", KeyOutputFormat.DerHex);
        Select(tool, "key-public-format", KeyOutputFormat.DerBase64);
        Assert.Equal(ReadDer(privatePem), Convert.FromHexString(Find<IUIMultiLineTextInput>(tool, "key-private").Text));
        Assert.Equal(ReadDer(publicPem), Convert.FromBase64String(Find<IUIMultiLineTextInput>(tool, "key-public").Text));
        Select(tool, "key-private-format", KeyOutputFormat.DerBase64);
        Select(tool, "key-public-format", KeyOutputFormat.DerHex);
        Assert.Equal(ReadDer(privatePem), Convert.FromBase64String(Find<IUIMultiLineTextInput>(tool, "key-private").Text));
        Assert.Equal(ReadDer(publicPem), Convert.FromHexString(Find<IUIMultiLineTextInput>(tool, "key-public").Text));
        Select(tool, "key-private-format", KeyOutputFormat.Pkcs8Pem);
        Select(tool, "key-public-format", KeyOutputFormat.Pem);
        Assert.Equal(privatePem, Find<IUIMultiLineTextInput>(tool, "key-private").Text);
        Assert.Equal(publicPem, Find<IUIMultiLineTextInput>(tool, "key-public").Text);
    }

    [Fact]
    public async Task GeneratingAFixedCurveKeyResetsUnsupportedTraditionalFormats()
    {
        var tool = new KeyGeneratorTool();
        await Click(tool, "key-generate");
        Select(tool, "key-private-format", KeyOutputFormat.TraditionalPem);
        Select(tool, "key-public-format", KeyOutputFormat.TraditionalPem);
        Select(tool, "key-algorithm", "Ed25519");
        Assert.Null(tool.View.GetChildElementById("key-rsa-size"));
        Assert.Null(tool.View.GetChildElementById("key-curve"));
        await Click(tool, "key-generate");
        var privateFormats = Find<IUISelectDropDownList>(tool, "key-private-format");
        var publicFormats = Find<IUISelectDropDownList>(tool, "key-public-format");
        Assert.DoesNotContain(privateFormats.Items!, item => Equals(item.Value, KeyOutputFormat.TraditionalPem));
        Assert.DoesNotContain(publicFormats.Items!, item => Equals(item.Value, KeyOutputFormat.TraditionalPem));
        Assert.Equal(KeyOutputFormat.Pkcs8Pem, privateFormats.SelectedItem!.Value);
        Assert.Equal(KeyOutputFormat.Pem, publicFormats.SelectedItem!.Value);
        Assert.IsAssignableFrom<Ed25519PrivateKeyParameters>(KeyGenerator.ReadKey(Find<IUIMultiLineTextInput>(tool, "key-private").Text, true));
    }

    private static byte[] ReadDer(string pem)
    {
        var fields = PemEncoding.Find(pem);
        return Convert.FromBase64String(pem[fields.Base64Data]);
    }
    private static T Find<T>(KeyGeneratorTool tool, string id) where T : IUIElement => Assert.IsAssignableFrom<T>(tool.View.GetChildElementById(id));
    private static async Task Click(KeyGeneratorTool tool, string id) => await Find<IUIButton>(tool, id).OnClickAction!();
    private static void Select(KeyGeneratorTool tool, string id, object value)
    {
        var control = Find<IUISelectDropDownList>(tool, id);
        control.Select(control.Items!.Single(item => Equals(item.Value, value)));
    }
}
