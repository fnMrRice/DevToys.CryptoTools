using System.Security.Cryptography;
using System.Text;

namespace DevToys.CryptoTools.UI;

internal static class KeyPairFileExport
{
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static async ValueTask ExportAsync(string directory, string baseName, string privateKeyPem, string publicKeyPem)
    {
        if (string.IsNullOrWhiteSpace(privateKeyPem) || string.IsNullOrWhiteSpace(publicKeyPem))
            throw new ArgumentException(L("KeyExportMissingKeys"));

        string outputDirectory = ValidateDirectory(directory);
        ValidateName(baseName);
        string privatePath = Path.Combine(outputDirectory, baseName + ".key");
        string publicPath = Path.Combine(outputDirectory, baseName + ".pub");
        bool privateCreated = false;
        bool publicCreated = false;
        try
        {
            await using FileStream privateFile = CreateNew(privatePath);
            privateCreated = true;
            await using FileStream publicFile = CreateNew(publicPath);
            publicCreated = true;
            await WritePemAsync(privateFile, privateKeyPem).ConfigureAwait(false);
            await WritePemAsync(publicFile, publicKeyPem).ConfigureAwait(false);
        }
        catch
        {
            // The using declarations release handles before entering this catch.
            // Only paths whose CreateNew operation succeeded belong to this export.
            if (publicCreated)
                TryDeleteCreated(publicPath);
            if (privateCreated)
                TryDeleteCreated(privatePath);
            throw;
        }
    }

    private static string ValidateDirectory(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Path.IsPathFullyQualified(directory))
            throw new ArgumentException(L("KeyExportInvalidDirectory"), nameof(directory));
        string fullPath;
        try { fullPath = Path.GetFullPath(directory); }
        catch (Exception error) when (error is ArgumentException or NotSupportedException or PathTooLongException)
        {
            throw new ArgumentException(L("KeyExportInvalidDirectory"), nameof(directory), error);
        }
        if (!Directory.Exists(fullPath))
            throw new ArgumentException(L("KeyExportInvalidDirectory"), nameof(directory));
        return fullPath;
    }

    private static void ValidateName(string baseName)
    {
        if (string.IsNullOrWhiteSpace(baseName) || baseName.IndexOfAny(Path.GetInvalidFileNameChars()) >= 0 ||
            baseName.IndexOfAny(['<', '>', ':', '"', '/', '\\', '|', '?', '*']) >= 0 ||
            baseName.Any(char.IsControl) || baseName.EndsWith(' ') || baseName.EndsWith('.'))
            throw new ArgumentException(L("KeyExportInvalidName"), nameof(baseName));

        // Windows device names remain reserved when followed by an extension.
        string stem = baseName.Split('.')[0].TrimEnd(' ');
        if (stem.Equals("CON", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("PRN", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("AUX", StringComparison.OrdinalIgnoreCase) ||
            stem.Equals("NUL", StringComparison.OrdinalIgnoreCase) ||
            (stem.Length == 4 &&
                (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) || stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) &&
                "123456789¹²³".Contains(stem[3])))
            throw new ArgumentException(L("KeyExportInvalidName"), nameof(baseName));
    }

    private static FileStream CreateNew(string path)
    {
        try
        {
            return new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None, 4096, FileOptions.Asynchronous);
        }
        catch (Exception error) when ((error is IOException or UnauthorizedAccessException) && (File.Exists(path) || Directory.Exists(path)))
        {
            throw new IOException(L("KeyExportFileExists"), error);
        }
    }

    private static async ValueTask WritePemAsync(Stream stream, string pem)
    {
        byte[] bytes = Utf8.GetBytes(pem);
        try { await stream.WriteAsync(bytes.AsMemory()).ConfigureAwait(false); }
        finally { CryptographicOperations.ZeroMemory(bytes); }
    }

    private static void TryDeleteCreated(string path)
    {
        try { File.Delete(path); }
        catch (IOException) { }
        catch (UnauthorizedAccessException) { }
    }
}
