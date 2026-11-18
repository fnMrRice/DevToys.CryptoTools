using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DevToys.CryptoTools.Cryptography;

internal static class SymmetricCipher
{
    internal static int IvLength(string algorithm) => algorithm switch
    {
        "AES-CBC" or "SM4-CBC" => 16,
        "AES-GCM" or "SM4-GCM" or "ChaCha20-Poly1305" => 12,
        _ => throw new ArgumentException(L("InvalidAlgorithm"))
    };

    // Authenticated modes return ciphertext followed by the 16-byte authentication tag.
    internal static byte[] Transform(bool encrypt, string algorithm, byte[] key, byte[] iv, byte[] input,
        PaddingMode padding = PaddingMode.None, byte[]? associatedData = null)
    {
        Validate(algorithm, key, iv, padding);
        if (algorithm.EndsWith("-CBC", StringComparison.Ordinal))
        {
            if (algorithm == "AES-CBC")
            {
                using var aes = Aes.Create();
                aes.Key = key;
                return encrypt ? aes.EncryptCbc(input, iv, padding) : aes.DecryptCbc(input, iv, padding);
            }
            var cipher = CipherUtilities.GetCipher("SM4/CBC/" + (padding == PaddingMode.PKCS7 ? "PKCS7Padding" : "NoPadding"));
            cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
            return cipher.DoFinal(input);
        }

        if (!encrypt && input.Length < 16) throw new ArgumentException(L("InvalidCiphertext"));
        if (algorithm == "SM4-GCM")
        {
            var cipher = CipherUtilities.GetCipher("SM4/GCM/NoPadding");
            cipher.Init(encrypt, new AeadParameters(new KeyParameter(key), 128, iv, associatedData));
            return cipher.DoFinal(input);
        }

        byte[] output = new byte[encrypt ? input.Length + 16 : input.Length - 16];
        ReadOnlySpan<byte> ciphertext = encrypt ? default : input.AsSpan(0, input.Length - 16);
        ReadOnlySpan<byte> tag = encrypt ? default : input.AsSpan(input.Length - 16);
        if (algorithm == "AES-GCM")
        {
            using var aes = new AesGcm(key, 16);
            if (encrypt) aes.Encrypt(iv, input, output.AsSpan(0, input.Length), output.AsSpan(input.Length), associatedData);
            else aes.Decrypt(iv, ciphertext, tag, output, associatedData);
        }
        else
        {
            using var chacha = new ChaCha20Poly1305(key);
            if (encrypt) chacha.Encrypt(iv, input, output.AsSpan(0, input.Length), output.AsSpan(input.Length), associatedData);
            else chacha.Decrypt(iv, ciphertext, tag, output, associatedData);
        }
        return output;
    }

    private static void Validate(string algorithm, byte[] key, byte[] iv, PaddingMode padding)
    {
        int length = IvLength(algorithm);
        bool validKey = algorithm switch
        {
            "AES-GCM" or "AES-CBC" => key.Length is 16 or 24 or 32,
            "ChaCha20-Poly1305" => key.Length == 32,
            _ => key.Length == 16
        };
        if (!validKey) throw new ArgumentException(L("InvalidKeySize"));
        if (iv.Length != length) throw new ArgumentException(string.Format(System.Globalization.CultureInfo.CurrentCulture, L("InvalidIvSize"), length));
        if (padding is not (PaddingMode.None or PaddingMode.PKCS7)
            || (!algorithm.EndsWith("-CBC", StringComparison.Ordinal) && padding != PaddingMode.None))
            throw new ArgumentException(L("InvalidPadding"));
    }
}
