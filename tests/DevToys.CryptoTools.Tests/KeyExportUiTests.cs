using System.Security.Cryptography;
using DevToys.Api;
using DevToys.CryptoTools.Cryptography;
using DevToys.CryptoTools.Tools;
using static DevToys.Api.GUI;

namespace DevToys.CryptoTools.Tests;

public class KeyExportUiTests
{
    [Fact]
    public async Task ExportUsesSelectedFolderAndNameAndPreservesTheEncryptedPrivateKey()
    {
        var directory = Directory.CreateTempSubdirectory("DevToys.KeyExportUi-");
        try
        {
            var storage = new FolderPicker(directory.FullName);
            var tool = new KeyGeneratorTool { FileStorage = storage };
            SelectEd25519(tool);
            Find<IUIPasswordInput>(tool, "key-password").Text("file export password");
            await Click(tool, "key-generate");
            string privateKey = Find<IUIMultiLineTextInput>(tool, "key-private").Text;
            string publicKey = Find<IUIMultiLineTextInput>(tool, "key-public").Text;
            Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", privateKey);
            Find<IUISingleLineTextInput>(tool, "key-export-name").Text("client-key");
            await Click(tool, "key-export");
            Assert.Equal(1, storage.PickCount);
            Assert.Equal(privateKey, await File.ReadAllTextAsync(Path.Combine(directory.FullName, "client-key.key")));
            Assert.Equal(publicKey, await File.ReadAllTextAsync(Path.Combine(directory.FullName, "client-key.pub")));
            Assert.True(Find<IUIButton>(tool, "key-export").IsEnabled);
        }
        finally { directory.Delete(true); }
    }

    [Fact]
    public async Task CancellingFolderSelectionWritesNothingAndRestoresTheButtons()
    {
        var directory = Directory.CreateTempSubdirectory("DevToys.KeyExportCancel-");
        try
        {
            var storage = new FolderPicker(null);
            var tool = new KeyGeneratorTool { FileStorage = storage };
            SelectEd25519(tool);
            await Click(tool, "key-generate");
            Find<IUISingleLineTextInput>(tool, "key-export-name").Text(Path.Combine(directory.FullName, "should-not-exist"));
            await Click(tool, "key-export");
            Assert.Equal(1, storage.PickCount);
            Assert.Empty(directory.EnumerateFileSystemInfos());
            Assert.True(Find<IUIButton>(tool, "key-generate").IsEnabled);
            Assert.True(Find<IUIButton>(tool, "key-export").IsEnabled);
        }
        finally { directory.Delete(true); }
    }

    [Theory]
    [InlineData("", "new export password")]
    [InlineData("old export password", "new export password")]
    [InlineData("old export password", "")]
    public async Task ExportKeepsThePasswordUsedWhenGeneratingTheKeyPair(string originalPassword, string currentPassword)
    {
        var directory = Directory.CreateTempSubdirectory("DevToys.KeyExportPassword-");
        try
        {
            var tool = new KeyGeneratorTool { FileStorage = new FolderPicker(directory.FullName) };
            var password = Find<IUIPasswordInput>(tool, "key-password");
            password.Text(originalPassword);
            await Click(tool, "key-generate");
            string generatedPrivateKey = Find<IUIMultiLineTextInput>(tool, "key-private").Text;
            string generatedPublicKey = Find<IUIMultiLineTextInput>(tool, "key-public").Text;
            using var original = RSA.Create();
            if (originalPassword.Length == 0) original.ImportFromPem(generatedPrivateKey);
            else original.ImportFromEncryptedPem(generatedPrivateKey, originalPassword);

            password.Text(currentPassword);
            await Click(tool, "key-export");
            string exported = await File.ReadAllTextAsync(Path.Combine(directory.FullName, "keypair.key"));
            using var restored = RSA.Create();
            if (originalPassword.Length == 0)
            {
                Assert.StartsWith("-----BEGIN PRIVATE KEY-----", exported);
                restored.ImportFromPem(exported);
            }
            else
            {
                Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", exported);
                restored.ImportFromEncryptedPem(exported, originalPassword);
                string wrongPassword = currentPassword.Length == 0 ? "wrong password" : currentPassword;
                using var wrongPasswordReader = RSA.Create();
                Assert.Throws<CryptographicException>(() => wrongPasswordReader.ImportFromEncryptedPem(exported, wrongPassword));
            }
            Assert.Equal(original.ExportPkcs8PrivateKey(), restored.ExportPkcs8PrivateKey());
            Assert.Equal(generatedPrivateKey, exported);
            Assert.Equal(generatedPublicKey, restored.ExportSubjectPublicKeyInfoPem());
            Assert.Equal(generatedPublicKey, await File.ReadAllTextAsync(Path.Combine(directory.FullName, "keypair.pub")));
            Assert.Equal(generatedPublicKey, Find<IUIMultiLineTextInput>(tool, "key-public").Text);
            Assert.Equal(exported, Find<IUIMultiLineTextInput>(tool, "key-private").Text);
        }
        finally { directory.Delete(true); }
    }

    [Theory]
    [InlineData((int)KeyOutputFormat.DerHex, (int)KeyOutputFormat.DerBase64)]
    [InlineData((int)KeyOutputFormat.DerBase64, (int)KeyOutputFormat.DerHex)]
    public async Task DerFormatsExportBinaryAndRetainTheGeneratedPassword(int privateFormatValue, int publicFormatValue)
    {
        var directory = Directory.CreateTempSubdirectory("DevToys.KeyExportDer-");
        try
        {
            var tool = new KeyGeneratorTool { FileStorage = new FolderPicker(directory.FullName) };
            const string generatedPassword = "DER export password";
            Find<IUIPasswordInput>(tool, "key-password").Text(generatedPassword);
            await Click(tool, "key-generate");
            string protectedPem = Find<IUIMultiLineTextInput>(tool, "key-private").Text;
            string publicPem = Find<IUIMultiLineTextInput>(tool, "key-public").Text;
            Find<IUIPasswordInput>(tool, "key-password").Text("a later password");
            Select(tool, "key-private-format", (KeyOutputFormat)privateFormatValue);
            Select(tool, "key-public-format", (KeyOutputFormat)publicFormatValue);
            Assert.DoesNotContain(Find<IUISelectDropDownList>(tool, "key-private-format").Items!, item => Equals(item.Value, KeyOutputFormat.TraditionalPem));
            await Click(tool, "key-export");
            byte[] privateDer = await File.ReadAllBytesAsync(Path.Combine(directory.FullName, "keypair.key"));
            byte[] publicDer = await File.ReadAllBytesAsync(Path.Combine(directory.FullName, "keypair.pub"));
            Assert.Equal(ReadDer(protectedPem), privateDer);
            Assert.Equal(ReadDer(publicPem), publicDer);
            using var restored = RSA.Create();
            restored.ImportEncryptedPkcs8PrivateKey(generatedPassword, privateDer, out int read);
            Assert.Equal(privateDer.Length, read);
            Assert.Equal(publicPem, restored.ExportSubjectPublicKeyInfoPem());
            using var wrongPasswordReader = RSA.Create();
            Assert.Throws<CryptographicException>(() => wrongPasswordReader.ImportEncryptedPkcs8PrivateKey("a later password", privateDer, out _));
            Select(tool, "key-private-format", KeyOutputFormat.Pkcs8Pem);
            Assert.Equal(protectedPem, Find<IUIMultiLineTextInput>(tool, "key-private").Text);
        }
        finally { directory.Delete(true); }
    }

    private static void SelectEd25519(KeyGeneratorTool tool)
    {
        var algorithm = Find<IUISelectDropDownList>(tool, "key-algorithm");
        algorithm.Select(algorithm.Items!.Single(item => Equals(item.Value, "Ed25519")));
    }
    private static T Find<T>(KeyGeneratorTool tool, string id) where T : IUIElement => Assert.IsAssignableFrom<T>(tool.View.GetChildElementById(id));
    private static async Task Click(KeyGeneratorTool tool, string id) => await Find<IUIButton>(tool, id).OnClickAction!();
    private static void Select(KeyGeneratorTool tool, string id, object value)
    {
        var control = Find<IUISelectDropDownList>(tool, id);
        control.Select(control.Items!.Single(item => Equals(item.Value, value)));
    }
    private static byte[] ReadDer(string pem)
    {
        var fields = PemEncoding.Find(pem);
        return Convert.FromBase64String(pem[fields.Base64Data]);
    }

    private sealed class FolderPicker(string? directory) : IFileStorage
    {
        public int PickCount { get; private set; }
        public string AppCacheDirectory => throw new NotSupportedException();
        public ValueTask<string?> PickFolderAsync() { PickCount++; return ValueTask.FromResult(directory); }
        public ValueTask<FileStream?> PickSaveFileAsync(params string[] fileTypes) => throw new NotSupportedException();
        public ValueTask<SandboxedFileReader?> PickOpenFileAsync(params string[] fileTypes) => throw new NotSupportedException();
        public ValueTask<SandboxedFileReader[]> PickOpenFilesAsync(params string[] fileTypes) => throw new NotSupportedException();
        public bool FileExists(string relativeOrAbsoluteFilePath) => throw new NotSupportedException();
        public FileStream OpenReadFile(string relativeOrAbsoluteFilePath) => throw new NotSupportedException();
        public FileStream OpenWriteFile(string relativeOrAbsoluteFilePath, bool replaceIfExist) => throw new NotSupportedException();
        public FileInfo CreateSelfDestroyingTempFile(string? desiredFileExtension = null) => throw new NotSupportedException();
    }
}
