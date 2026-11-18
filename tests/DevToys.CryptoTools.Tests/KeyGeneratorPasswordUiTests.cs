using System.Security.Cryptography;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.Tools;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tests;

public class KeyGeneratorPasswordUiTests
{
    [Fact]
    public async Task ProtectedOutputCanStillBeSentDirectlyToCreateACsr()
    {
        var tool = new KeyGeneratorTool();
        var algorithm = Find<IUISelectDropDownList>(tool, "key-algorithm");
        algorithm.Select(algorithm.Items!.Single(item => Equals(item.Value, "SM2")));
        var password = Find<IUIPasswordInput>(tool, "key-password");
        password.Text("CSR export password");
        await Click(tool, "key-generate");
        string protectedKey = Find<IUIMultiLineTextInput>(tool, "key-private").Text;
        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", protectedKey);
        byte[] expectedKey = PrivateKeyInfoFactory.CreatePrivateKeyInfo("CSR export password".ToCharArray(), EncryptedPrivateKeyInfo.GetInstance(ReadDer(protectedKey))).GetDerEncoded();
        string publicKey = Find<IUIMultiLineTextInput>(tool, "key-public").Text;
        await Click(tool, "key-send-csr");
        string transferredKey = Find<IUIMultiLineTextInput>(tool, "csr-key-pem").Text;
        Assert.StartsWith("-----BEGIN PRIVATE KEY-----", transferredKey);
        Assert.Equal(expectedKey, ReadDer(transferredKey));
        await Click(tool, "csr-generate");
        var request = CertificateRequestService.Inspect(System.Text.Encoding.UTF8.GetBytes(Find<IUIMultiLineTextInput>(tool, "csr-output").Text));
        Assert.Equal(publicKey, request.PublicKeyPem);
    }

    [Fact]
    public async Task ClearErasesTheExportPasswordAndGeneratedKeys()
    {
        var tool = new KeyGeneratorTool();
        var password = Find<IUIPasswordInput>(tool, "key-password");
        password.Text("do not retain this password");
        Find<IUIMultiLineTextInput>(tool, "key-private").Text("previous private key");
        Find<IUIMultiLineTextInput>(tool, "key-public").Text("previous public key");
        await Click(tool, "key-clear");
        Assert.Empty(password.Text);
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "key-private").Text);
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "key-public").Text);
    }

    private static byte[] ReadDer(string pem)
    {
        var fields = PemEncoding.Find(pem);
        return Convert.FromBase64String(pem[fields.Base64Data]);
    }
    private static T Find<T>(KeyGeneratorTool tool, string id) where T : IUIElement => Assert.IsAssignableFrom<T>(tool.View.GetChildElementById(id));
    private static async Task Click(KeyGeneratorTool tool, string id) => await Find<IUIButton>(tool, id).OnClickAction!();
}
