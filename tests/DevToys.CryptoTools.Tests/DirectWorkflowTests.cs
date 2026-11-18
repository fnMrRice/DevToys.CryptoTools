using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.Tools;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tests;

public class DirectWorkflowTests
{
    [Theory]
    [InlineData("SM2")]
    [InlineData("Ed25519")]
    [InlineData("ECDSA-secp256k1")]
    public async Task KeyPairCanBeSentThroughCsrAndCertificateFormsWithoutClipboard(string algorithm)
    {
        var tool = new KeyGeneratorTool();
        var algorithms = Find<IUISelectDropDownList>(tool, "key-algorithm");
        algorithms.Select(algorithms.Items!.Single(i => Equals(i.Value, algorithm)));
        await Click(tool, "key-generate");
        string privateKey = Find<IUIMultiLineTextInput>(tool, "key-private").Text;
        await Click(tool, "key-send-csr");
        Assert.Equal(privateKey, Find<IUIMultiLineTextInput>(tool, "csr-key-pem").Text);
        Find<IUISingleLineTextInput>(tool, "csr-CommonName").Text("workflow.example");
        var preset = Find<IUISelectDropDownList>(tool, "csr-preset");
        preset.Select(preset.Items!.Single(i => Equals(i.Value, "CodeSigning")));
        await Click(tool, "csr-generate");
        string request = Find<IUIMultiLineTextInput>(tool, "csr-output").Text;
        Assert.Contains("BEGIN CERTIFICATE REQUEST", request);
        await Click(tool, "csr-issue");
        Assert.Equal(request, Find<IUIMultiLineTextInput>(tool, "cert-csr").Text);
        await Click(tool, "cert-generate");
        string pem = Find<IUIMultiLineTextInput>(tool, "cert-output").Text;
        Assert.Contains("BEGIN CERTIFICATE", pem);
        var certificate = CertificateGenerator.ReadCertificate(System.Text.Encoding.UTF8.GetBytes(pem));
        Assert.Contains("CN=workflow.example", certificate.SubjectDN.ToString());
        certificate.Verify(certificate.GetPublicKey());
        Assert.Contains(KeyPurposeID.id_kp_codeSigning.Id, certificate.GetExtendedKeyUsage()!.Select(oid => oid.Id));
        Assert.Equal(privateKey, Find<IUIMultiLineTextInput>(tool, "cert-private-output").Text);
    }

    private static T Find<T>(IGuiTool tool, string id) where T : IUIElement => Assert.IsAssignableFrom<T>(tool.View.GetChildElementById(id));
    private static async Task Click(IGuiTool tool, string id) => await Find<IUIButton>(tool, id).OnClickAction!();
}
