using System.Security.Cryptography;
using DevToys.Api;

namespace DevToys.CryptoTools.UI;

internal static class FileImport
{
    internal static async ValueTask<byte[]> ReadAsync(SandboxedFileReader[] files, int maximumBytes = 1024 * 1024)
    {
        try
        {
            if (files.Length != 1) throw new ArgumentException(L("SelectOneFile"));
            using var stream = await files[0].GetNewAccessToFileContentAsync(CancellationToken.None);
            using var output = new MemoryStream();
            byte[] buffer = new byte[8192];
            try
            {
                int count;
                while ((count = await stream.ReadAsync(buffer)) > 0)
                {
                    if (output.Length + count > maximumBytes) throw new ArgumentException(L("FileTooLarge"));
                    await output.WriteAsync(buffer.AsMemory(0, count));
                }
                return output.ToArray();
            }
            finally
            {
                CryptographicOperations.ZeroMemory(buffer);
                if (output.TryGetBuffer(out var content)) CryptographicOperations.ZeroMemory(content.AsSpan());
            }
        }
        finally { foreach (var file in files) file.Dispose(); }
    }
}
