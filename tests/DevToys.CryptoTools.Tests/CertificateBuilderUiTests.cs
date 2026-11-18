using System.Text;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.Tools;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.X509;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tests;

public class CertificateBuilderUiTests
{
    [Fact]
    public async Task StructuredFieldsExtensionsAndPresetReachGeneratedCertificate()
    {
        var tool = new CertificateGeneratorTool();
        Select(tool, "cert-algorithm", "SM2");
        Select(tool, "cert-preset", "DocumentSigning");
        Find<IUISingleLineTextInput>(tool, "cert-CommonName").Text("Test Signer");
        Find<IUISingleLineTextInput>(tool, "cert-Organization").Text("Example, Inc");
        Find<IUISingleLineTextInput>(tool, "cert-Country").Text("CN");
        Find<IUISingleLineTextInput>(tool, "cert-SerialHex").Text("1234");
        Find<IUISingleLineTextInput>(tool, "cert-SanIp").Text("127.0.0.1");
        Find<IUISingleLineTextInput>(tool, "cert-SanEmail").Text("test@example.test");
        Find<IUISingleLineTextInput>(tool, "cert-SanUri").Text("https://example.test");
        Find<IUISingleLineTextInput>(tool, "cert-CustomEkuOids").Text("1.2.3.4");
        await Click(tool, "cert-generate");
        string pem = Find<IUIMultiLineTextInput>(tool, "cert-output").Text;
        Assert.NotEmpty(pem);
        var certificate = new X509CertificateParser().ReadCertificate(Encoding.UTF8.GetBytes(pem));
        certificate.Verify(certificate.GetPublicKey());
        Assert.Equal("1234", certificate.SerialNumber.ToString(16));
        Assert.Contains("Test Signer", certificate.SubjectDN.ToString());
        Assert.Contains("Example", certificate.SubjectDN.ToString());
        var eku = certificate.GetExtendedKeyUsage()!.Select(oid => oid.Id).ToArray();
        Assert.Contains("1.3.6.1.4.1.311.10.3.12", eku);
        Assert.Contains("1.2.3.4", eku);
        Assert.Equal(4, certificate.GetSubjectAlternativeNames()!.Count);
    }

    [Fact]
    public void CaAndSanSwitchesUpdateRelatedFields()
    {
        var tool = new CertificateGeneratorTool();
        Assert.False(Find<IUISingleLineTextInput>(tool, "cert-PathLength").IsEnabled);
        Find<IUISwitch>(tool, "cert-IsCa").On();
        Assert.True(Find<IUISingleLineTextInput>(tool, "cert-PathLength").IsEnabled);
        Find<IUISwitch>(tool, "cert-IncludeSan").Off();
        Assert.False(Find<IUISingleLineTextInput>(tool, "cert-SanDns").IsEnabled);
        Select(tool, "cert-algorithm", "Ed25519");
        Assert.False(Find<IUISelectDropDownList>(tool, "cert-hash").IsEnabled);
        Assert.False(Find<IUISwitch>(tool, "cert-RsaPss").IsEnabled);
    }

    [Fact]
    public async Task CsrFileImportPreservesSubjectAndPublicKeyForIssuance()
    {
        var original = CertificateRequestService.Generate(new CertificateOptions
        {
            Algorithm = "SM2", Subject = "CN=Imported CSR,O=Original", DnsNames = ["csr.example.test"], IpAddresses = ["127.0.0.1"]
        });
        var tool = new CertificateGeneratorTool();
        var selector = Find<IUIFileSelector>(tool, "cert-csr-file");
        var file = new MemoryFile("request.csr", Encoding.UTF8.GetBytes(original.Document));
        await selector.OnFilesSelectedAction!([file]);
        Assert.True(file.IsDisposed);
        Assert.Equal("Imported CSR", Find<IUISingleLineTextInput>(tool, "cert-CommonName").Text);
        tool.OnDataReceived(DraftTransfer.KeyPairDataType, new KeyPairDraft("SM2", "", original.PrivateKey));
        await Click(tool, "cert-generate");
        var certificate = new X509CertificateParser().ReadCertificate(Encoding.UTF8.GetBytes(Find<IUIMultiLineTextInput>(tool, "cert-output").Text));
        Assert.Equal(CertificateRequestService.Inspect(Encoding.UTF8.GetBytes(original.Document)).PublicKeyPem,
            CertificateRequestService.ExportPublic(certificate.GetPublicKey()));
    }

    [Fact]
    public async Task ImportedIssuerCaSignsLeafCertificate()
    {
        var issuer = CertificateGenerator.Generate(new CertificateOptions
        {
            Algorithm = "ECDSA-P256", Subject = "CN=Test CA", IsCa = true,
            KeyUsage = KeyUsage.KeyCertSign | KeyUsage.CrlSign, NotAfterUtc = DateTime.UtcNow.AddDays(730)
        });
        var tool = new CertificateGeneratorTool();
        Find<IUISwitch>(tool, "cert-use-issuer").On();
        var selector = Find<IUIFileSelector>(tool, "cert-issuer-file");
        await selector.OnFilesSelectedAction!([new MemoryFile("issuer.pem", Encoding.UTF8.GetBytes(issuer.Document))]);
        Find<IUIMultiLineTextInput>(tool, "cert-issuer-key-pem").Text(issuer.PrivateKey);
        await Click(tool, "cert-generate");
        var leaf = new X509CertificateParser().ReadCertificate(Encoding.UTF8.GetBytes(Find<IUIMultiLineTextInput>(tool, "cert-output").Text));
        var ca = new X509CertificateParser().ReadCertificate(Encoding.UTF8.GetBytes(issuer.Document));
        leaf.Verify(ca.GetPublicKey());
        Assert.Equal(ca.SubjectDN, leaf.IssuerDN);
    }

    [Fact]
    public async Task CsrEditsInvalidateOutputAndHandoffUsesCurrentFieldsAndAlgorithm()
    {
        var keys = KeyGenerator.Generate("SM2");
        var tool = new CertificateRequestTool();
        tool.OnDataReceived(DraftTransfer.KeyPairDataType, new KeyPairDraft("SM2", keys.PublicKey, keys.PrivateKey));
        await Click(tool, "csr-generate");
        Find<IUISingleLineTextInput>(tool, "csr-CommonName").Text("changed.example");
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "csr-output").Text);
        await Click(tool, "csr-issue");
        Assert.Equal("SM2", Find<IUISelectDropDownList>(tool, "cert-algorithm").SelectedItem!.Value);
        Assert.Equal("changed.example", Find<IUISingleLineTextInput>(tool, "cert-CommonName").Text);
        await Click(tool, "cert-generate");
        var certificate = CertificateGenerator.ReadCertificate(Encoding.UTF8.GetBytes(Find<IUIMultiLineTextInput>(tool, "cert-output").Text));
        Assert.Contains("CN=changed.example", certificate.SubjectDN.ToString());
        Assert.Equal(keys.PrivateKey, Find<IUIMultiLineTextInput>(tool, "cert-private-output").Text);
    }

    [Fact]
    public async Task MalformedIssuerFileIsReportedAndDisposed()
    {
        var tool = new CertificateGeneratorTool();
        var file = new MemoryFile("bad.cer", [1, 2, 3]);
        await Find<IUIFileSelector>(tool, "cert-issuer-file").OnFilesSelectedAction!([file]);
        Assert.True(file.IsDisposed);
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "cert-issuer-certificate").Text);
    }

    [Fact]
    public void MismatchedKeyPairCannotPopulateTheCsrForm()
    {
        var first = KeyGenerator.Generate("ECDSA-P256");
        var second = KeyGenerator.Generate("ECDSA-P256");
        var tool = new CertificateRequestTool();
        Assert.Throws<ArgumentException>(() => tool.OnDataReceived(DraftTransfer.KeyPairDataType,
            new KeyPairDraft("ECDSA-P256", first.PublicKey, second.PrivateKey)));
        Assert.Empty(Find<IUIMultiLineTextInput>(tool, "csr-key-pem").Text);
    }

    private static T Find<T>(DevToys.CryptoTools.UI.CryptoToolBase tool, string id) where T : IUIElement => Assert.IsAssignableFrom<T>(tool.View.GetChildElementById(id));
    private static void Select(DevToys.CryptoTools.UI.CryptoToolBase tool, string id, string value)
    {
        var choice = Find<IUISelectDropDownList>(tool, id);
        choice.Select(choice.Items!.Single(item => Equals(item.Value, value)));
    }
    private static async Task Click(DevToys.CryptoTools.UI.CryptoToolBase tool, string id) => await Find<IUIButton>(tool, id).OnClickAction!();

    private sealed class MemoryFile(string name, byte[] content) : SandboxedFileReader(name)
    {
        internal bool IsDisposed { get; private set; }
        protected override ValueTask<Stream> OpenReadFileAsync(CancellationToken cancellationToken)
        {
            Disposed += (_, _) => IsDisposed = true;
            return ValueTask.FromResult<Stream>(new MemoryStream(content, writable: false));
        }
    }
}
