using System.Buffers;
using System.Text;
using DevToys.CryptoTools.UI;

namespace DevToys.CryptoTools.Tests;

public class KeyPairFileExportTests
{
    private const string PrivatePem = "-----BEGIN PRIVATE KEY-----\r\nAQIDBA==\r\n-----END PRIVATE KEY-----\r\n";
    private const string PublicPem = "-----BEGIN PUBLIC KEY-----\nBAUGBw==\n-----END PUBLIC KEY-----\n";
    private const string EncryptedPem = "-----BEGIN ENCRYPTED PRIVATE KEY-----\r\nMIIBvTBXBgkqhkiG9w0BBQ0wSjApBgkqhkiG9w0BBQwwHAQI\r\n-----END ENCRYPTED PRIVATE KEY-----\r\n";

    [Theory]
    [InlineData(PrivatePem)]
    [InlineData(EncryptedPem)]
    public async Task ExportCreatesMatchingKeyAndPubFilesPreservingPemWithoutBom(string privatePem)
    {
        using var directory = new TestDirectory();
        const string baseName = "我的密钥.client.v1";
        await KeyPairFileExport.ExportAsync(directory.FullName, baseName, privatePem, PublicPem);

        string privatePath = Path.Combine(directory.FullName, baseName + ".key");
        string publicPath = Path.Combine(directory.FullName, baseName + ".pub");
        Assert.Equal(Encoding.UTF8.GetBytes(privatePem), await File.ReadAllBytesAsync(privatePath));
        Assert.Equal(Encoding.UTF8.GetBytes(PublicPem), await File.ReadAllBytesAsync(publicPath));
        Assert.Equal(new[] { privatePath, publicPath }.Order(), Directory.GetFiles(directory.FullName).Order());
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" \t")]
    [InlineData(".")]
    [InlineData("..")]
    [InlineData("../outside")]
    [InlineData("..\\outside")]
    [InlineData("nested/keypair")]
    [InlineData("nested\\keypair")]
    [InlineData("C:\\outside")]
    [InlineData("/outside")]
    [InlineData("\\\\server\\share\\outside")]
    [InlineData("key:stream")]
    [InlineData("key*pair")]
    [InlineData("key?pair")]
    [InlineData("key|pair")]
    [InlineData("key\0pair")]
    [InlineData("keypair.")]
    [InlineData("keypair ")]
    [InlineData("CON")]
    [InlineData("nul.pem")]
    [InlineData("PRN")]
    [InlineData("aux.name")]
    [InlineData("COM1")]
    [InlineData("com9.name")]
    [InlineData("LPT1")]
    [InlineData("lpt9.name")]
    [InlineData("COM¹")]
    [InlineData("LPT².name")]
    public async Task ExportRejectsInvalidNamesWithoutCreatingFiles(string? baseName)
    {
        using var directory = new TestDirectory();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            KeyPairFileExport.ExportAsync(directory.FullName, baseName!, PrivatePem, PublicPem).AsTask());
        Assert.Empty(Directory.GetFileSystemEntries(directory.FullName));
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData(" \t")]
    [InlineData(".")]
    [InlineData("relative-directory")]
    [InlineData("C:\\invalid\0directory")]
    public async Task ExportRejectsInvalidDirectories(string? directory) =>
        await Assert.ThrowsAsync<ArgumentException>(() =>
            KeyPairFileExport.ExportAsync(directory!, "keypair", PrivatePem, PublicPem).AsTask());

    [Fact]
    public async Task ExportDoesNotCreateMissingDirectoriesOrUseAFileAsADirectory()
    {
        using var directory = new TestDirectory();
        string missing = Path.Combine(directory.FullName, "missing");
        await Assert.ThrowsAsync<ArgumentException>(() =>
            KeyPairFileExport.ExportAsync(missing, "keypair", PrivatePem, PublicPem).AsTask());
        Assert.False(Directory.Exists(missing));

        string existingFile = Path.Combine(directory.FullName, "existing.txt");
        await File.WriteAllTextAsync(existingFile, "original");
        await Assert.ThrowsAsync<ArgumentException>(() =>
            KeyPairFileExport.ExportAsync(existingFile, "keypair", PrivatePem, PublicPem).AsTask());
        Assert.Equal("original", await File.ReadAllTextAsync(existingFile));
    }

    [Theory]
    [InlineData(null, PublicPem)]
    [InlineData("", PublicPem)]
    [InlineData(" \r\n", PublicPem)]
    [InlineData(PrivatePem, null)]
    [InlineData(PrivatePem, "")]
    [InlineData(PrivatePem, " \r\n")]
    public async Task ExportRequiresBothKeysBeforeCreatingFiles(string? privatePem, string? publicPem)
    {
        using var directory = new TestDirectory();
        await Assert.ThrowsAsync<ArgumentException>(() =>
            KeyPairFileExport.ExportAsync(directory.FullName, "keypair", privatePem!, publicPem!).AsTask());
        Assert.Empty(Directory.GetFileSystemEntries(directory.FullName));
    }

    [Fact]
    public async Task ExistingPrivateKeyIsNeverOverwrittenAndNoPublicKeyIsCreated()
    {
        using var directory = new TestDirectory();
        string privatePath = Path.Combine(directory.FullName, "keypair.key");
        await File.WriteAllBytesAsync(privatePath, [1, 2, 3, 255]);
        await Assert.ThrowsAsync<IOException>(() =>
            KeyPairFileExport.ExportAsync(directory.FullName, "keypair", PrivatePem, PublicPem).AsTask());
        Assert.Equal(new byte[] { 1, 2, 3, 255 }, await File.ReadAllBytesAsync(privatePath));
        Assert.False(File.Exists(Path.Combine(directory.FullName, "keypair.pub")));
    }

    [Fact]
    public async Task ExistingPublicKeyIsPreservedAndOnlyTheNewPrivateKeyIsRolledBack()
    {
        using var directory = new TestDirectory();
        string publicPath = Path.Combine(directory.FullName, "keypair.pub");
        await File.WriteAllBytesAsync(publicPath, [4, 5, 6, 255]);
        await Assert.ThrowsAsync<IOException>(() =>
            KeyPairFileExport.ExportAsync(directory.FullName, "keypair", PrivatePem, PublicPem).AsTask());
        Assert.Equal(new byte[] { 4, 5, 6, 255 }, await File.ReadAllBytesAsync(publicPath));
        Assert.False(File.Exists(Path.Combine(directory.FullName, "keypair.key")));
        Assert.Equal(new[] { publicPath }, Directory.GetFiles(directory.FullName));
    }

    [Fact]
    public async Task ExistingPublicDirectoryIsPreservedWhenPrivateCreationIsRolledBack()
    {
        using var directory = new TestDirectory();
        string publicPath = Path.Combine(directory.FullName, "keypair.pub");
        Directory.CreateDirectory(publicPath);
        string sentinel = Path.Combine(publicPath, "existing.txt");
        await File.WriteAllTextAsync(sentinel, "original");
        await Assert.ThrowsAsync<IOException>(() =>
            KeyPairFileExport.ExportAsync(directory.FullName, "keypair", PrivatePem, PublicPem).AsTask());
        Assert.Equal("original", await File.ReadAllTextAsync(sentinel));
        Assert.False(File.Exists(Path.Combine(directory.FullName, "keypair.key")));
    }

    [Fact]
    public async Task TextEncodingFailureCreatesNoFiles()
    {
        using var directory = new TestDirectory();
        await Assert.ThrowsAsync<EncoderFallbackException>(() =>
            KeyPairFileExport.ExportAsync(directory.FullName, "keypair", PrivatePem, "\uD800").AsTask());
        Assert.Empty(Directory.GetFileSystemEntries(directory.FullName));
    }

    [Fact]
    public async Task BinaryExportWritesExactMemorySlicesWithoutChangingCallerBuffers()
    {
        using var directory = new TestDirectory();
        byte[] privateBytes = [9, 0, 255, 1, 10, 9];
        byte[] publicBytes = [9, 48, 130, 0, 254, 9];
        await KeyPairFileExport.ExportAsync(directory.FullName, "binary", privateBytes.AsMemory(1, 4), publicBytes.AsMemory(1, 4));
        Assert.Equal(new byte[] { 0, 255, 1, 10 }, await File.ReadAllBytesAsync(Path.Combine(directory.FullName, "binary.key")));
        Assert.Equal(new byte[] { 48, 130, 0, 254 }, await File.ReadAllBytesAsync(Path.Combine(directory.FullName, "binary.pub")));
        Assert.Equal(new byte[] { 9, 0, 255, 1, 10, 9 }, privateBytes);
        Assert.Equal(new byte[] { 9, 48, 130, 0, 254, 9 }, publicBytes);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task BinaryExportRequiresBothNonemptyKeys(bool privateEmpty)
    {
        using var directory = new TestDirectory();
        byte[] present = [1, 2, 3];
        ReadOnlyMemory<byte> privateBytes = privateEmpty ? ReadOnlyMemory<byte>.Empty : present;
        ReadOnlyMemory<byte> publicBytes = privateEmpty ? present : ReadOnlyMemory<byte>.Empty;
        await Assert.ThrowsAsync<ArgumentException>(() =>
            KeyPairFileExport.ExportAsync(directory.FullName, "binary", privateBytes, publicBytes).AsTask());
        Assert.Empty(Directory.GetFileSystemEntries(directory.FullName));
    }

    [Fact]
    public async Task BinaryExportConflictPreservesOriginalPublicBytesAndRollsBackNewPrivateFile()
    {
        using var directory = new TestDirectory();
        string publicPath = Path.Combine(directory.FullName, "binary.pub");
        await File.WriteAllBytesAsync(publicPath, [0, 1, 255]);
        await Assert.ThrowsAsync<IOException>(() => KeyPairFileExport.ExportAsync(directory.FullName, "binary",
            new byte[] { 1, 2, 3 }.AsMemory(), new byte[] { 4, 5, 6 }.AsMemory()).AsTask());
        Assert.Equal(new byte[] { 0, 1, 255 }, await File.ReadAllBytesAsync(publicPath));
        Assert.False(File.Exists(Path.Combine(directory.FullName, "binary.key")));
    }

    [Fact]
    public async Task BinarySecondWriteFailureRollsBackBothFilesCreatedByThisExport()
    {
        using var directory = new TestDirectory();
        using var failingMemory = new FailingMemory();
        await Assert.ThrowsAsync<IOException>(() => KeyPairFileExport.ExportAsync(directory.FullName, "binary",
            new byte[] { 1, 2, 3 }.AsMemory(), failingMemory.Bytes).AsTask());
        Assert.Empty(Directory.GetFileSystemEntries(directory.FullName));
    }

    [Fact]
    public async Task ConcurrentExportsCannotOverwriteOrDeleteTheWinningPair()
    {
        using var directory = new TestDirectory();
        Task<Exception?> first = Record.ExceptionAsync(() =>
            KeyPairFileExport.ExportAsync(directory.FullName, "keypair", "private-one", "public-one").AsTask());
        Task<Exception?> second = Record.ExceptionAsync(() =>
            KeyPairFileExport.ExportAsync(directory.FullName, "keypair", "private-two", "public-two").AsTask());
        Exception?[] results = await Task.WhenAll(first, second);
        Assert.Single(results, result => result is null);
        Assert.IsType<IOException>(Assert.Single(results, result => result is not null));

        string privateText = await File.ReadAllTextAsync(Path.Combine(directory.FullName, "keypair.key"));
        string publicText = await File.ReadAllTextAsync(Path.Combine(directory.FullName, "keypair.pub"));
        Assert.Contains(privateText, new[] { "private-one", "private-two" });
        Assert.Equal(privateText.Replace("private-", "public-", StringComparison.Ordinal), publicText);
    }

    private sealed class TestDirectory : IDisposable
    {
        private readonly DirectoryInfo _directory = Directory.CreateTempSubdirectory("DevToys.KeyPairExport.Tests-");
        internal string FullName => _directory.FullName;
        public void Dispose() => _directory.Delete(recursive: true);
    }

    private sealed class FailingMemory : MemoryManager<byte>
    {
        internal ReadOnlyMemory<byte> Bytes => CreateMemory(1);
        public override Span<byte> GetSpan() => throw new IOException("Cannot access the public key buffer.");
        public override MemoryHandle Pin(int elementIndex = 0) => throw new IOException("Cannot pin the public key buffer.");
        public override void Unpin() { }
        protected override void Dispose(bool disposing) { }
    }
}
