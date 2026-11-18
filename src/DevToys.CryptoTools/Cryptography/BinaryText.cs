using System.Text;

namespace DevToys.CryptoTools.Cryptography;

internal enum BinaryEncoding { Base64, Hex, Text }

internal static class BinaryText
{
    private static readonly UTF8Encoding Utf8 = new(false, true);

    internal static byte[] Decode(string text, BinaryEncoding encoding) => encoding switch
    {
        BinaryEncoding.Base64 => Convert.FromBase64String(text),
        BinaryEncoding.Hex => Convert.FromHexString(string.Concat(text.Where(c => !char.IsWhiteSpace(c)))),
        BinaryEncoding.Text => Utf8.GetBytes(text),
        _ => throw new ArgumentException(L("InvalidEncoding"))
    };

    internal static string Encode(byte[] bytes, BinaryEncoding encoding)
    {
        try
        {
            return encoding switch
            {
                BinaryEncoding.Base64 => Convert.ToBase64String(bytes),
                BinaryEncoding.Hex => Convert.ToHexString(bytes),
                BinaryEncoding.Text => Utf8.GetString(bytes),
                _ => throw new ArgumentException(L("InvalidEncoding"))
            };
        }
        catch (DecoderFallbackException)
        {
            throw new ArgumentException(L("InvalidTextEncoding"));
        }
    }
}
