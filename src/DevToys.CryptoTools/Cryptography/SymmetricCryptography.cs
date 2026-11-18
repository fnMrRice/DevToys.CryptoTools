using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DevToys.CryptoTools.Cryptography;

internal sealed record SymmetricEnvelope(int Version, string Algorithm, string Nonce, string Tag, string Ciphertext);

internal static class SymmetricCryptography
{
    internal static readonly string[] Algorithms = ["AES-GCM", "AES-CBC", "ChaCha20-Poly1305", "SM4-GCM", "SM4-CBC"];
    private static readonly JsonSerializerOptions JsonOptions = new(JsonSerializerDefaults.Web);

    internal static string Encrypt(string algorithm, string base64Key, string text)
    {
        byte[] key = DecodeKey(algorithm, base64Key);
        try
        {
            bool cbc = algorithm.EndsWith("-CBC", StringComparison.Ordinal);
            byte[] nonce = RandomNumberGenerator.GetBytes(cbc ? 16 : 12);
            byte[] plaintext = Encoding.UTF8.GetBytes(text);
            byte[] tag = cbc ? [] : new byte[16];
            byte[] ciphertext;
            if (cbc)
            {
                if (algorithm == "AES-CBC")
                {
                    using var aes = Aes.Create();
                    aes.Key = key;
                    ciphertext = aes.EncryptCbc(plaintext, nonce, PaddingMode.PKCS7);
                }
                else ciphertext = Sm4Cbc(true, key, nonce, plaintext);
            }
            else
            {
                ciphertext = new byte[plaintext.Length];
                if (algorithm == "AES-GCM")
                {
                    using var aes = new AesGcm(key, 16);
                    aes.Encrypt(nonce, plaintext, ciphertext, tag, Context(algorithm));
                }
                else if (algorithm == "ChaCha20-Poly1305")
                {
                    using var chacha = new ChaCha20Poly1305(key);
                    chacha.Encrypt(nonce, plaintext, ciphertext, tag, Context(algorithm));
                }
                else
                {
                    byte[] combined = Sm4Gcm(true, key, nonce, plaintext);
                    combined.AsSpan(0, plaintext.Length).CopyTo(ciphertext);
                    combined.AsSpan(plaintext.Length).CopyTo(tag);
                }
            }
            return JsonSerializer.Serialize(new SymmetricEnvelope(1, algorithm, Convert.ToBase64String(nonce), Convert.ToBase64String(tag), Convert.ToBase64String(ciphertext)), JsonOptions);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    internal static string Decrypt(string algorithm, string base64Key, string text)
    {
        byte[] key = DecodeKey(algorithm, base64Key);
        try
        {
            var envelope = JsonSerializer.Deserialize<SymmetricEnvelope>(text, JsonOptions);
            if (envelope is null || envelope.Version != 1 || envelope.Algorithm != algorithm
                || envelope.Nonce is null || envelope.Tag is null || envelope.Ciphertext is null)
                throw new ArgumentException(L("InvalidEnvelope"));
            bool cbc = algorithm.EndsWith("-CBC", StringComparison.Ordinal);
            byte[] nonce = Convert.FromBase64String(envelope.Nonce);
            byte[] tag = Convert.FromBase64String(envelope.Tag);
            byte[] ciphertext = Convert.FromBase64String(envelope.Ciphertext);
            if (nonce.Length != (cbc ? 16 : 12) || tag.Length != (cbc ? 0 : 16)) throw new ArgumentException(L("InvalidEnvelope"));
            byte[] plaintext;
            if (cbc)
            {
                if (ciphertext.Length == 0 || ciphertext.Length % 16 != 0) throw new ArgumentException(L("InvalidEnvelope"));
                if (algorithm == "AES-CBC")
                {
                    using var aes = Aes.Create();
                    aes.Key = key;
                    plaintext = aes.DecryptCbc(ciphertext, nonce, PaddingMode.PKCS7);
                }
                else plaintext = Sm4Cbc(false, key, nonce, ciphertext);
            }
            else
            {
                plaintext = new byte[ciphertext.Length];
                if (algorithm == "AES-GCM")
                {
                    using var aes = new AesGcm(key, 16);
                    aes.Decrypt(nonce, ciphertext, tag, plaintext, Context(algorithm));
                }
                else if (algorithm == "ChaCha20-Poly1305")
                {
                    using var chacha = new ChaCha20Poly1305(key);
                    chacha.Decrypt(nonce, ciphertext, tag, plaintext, Context(algorithm));
                }
                else plaintext = Sm4Gcm(false, key, nonce, [.. ciphertext, .. tag]);
            }
            return new UTF8Encoding(false, true).GetString(plaintext);
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    private static byte[] DecodeKey(string algorithm, string base64)
    {
        if (!Algorithms.Contains(algorithm)) throw new ArgumentException(L("InvalidAlgorithm"));
        byte[] key = Convert.FromBase64String(base64);
        bool valid = algorithm switch
        {
            "AES-GCM" or "AES-CBC" => key.Length is 16 or 24 or 32,
            "ChaCha20-Poly1305" => key.Length == 32,
            _ => key.Length == 16
        };
        if (!valid)
        {
            CryptographicOperations.ZeroMemory(key);
            throw new ArgumentException(L("InvalidKeySize"));
        }
        return key;
    }

    private static byte[] Context(string algorithm) => Encoding.UTF8.GetBytes("DevToys.CryptoTools.Symmetric.v1|" + algorithm);

    private static byte[] Sm4Cbc(bool encrypt, byte[] key, byte[] nonce, byte[] input)
    {
        var cipher = CipherUtilities.GetCipher("SM4/CBC/PKCS7Padding");
        cipher.Init(encrypt, new ParametersWithIV(new KeyParameter(key), nonce));
        return cipher.DoFinal(input);
    }

    private static byte[] Sm4Gcm(bool encrypt, byte[] key, byte[] nonce, byte[] input)
    {
        var cipher = CipherUtilities.GetCipher("SM4/GCM/NoPadding");
        cipher.Init(encrypt, new AeadParameters(new KeyParameter(key), 128, nonce, Context("SM4-GCM")));
        return cipher.DoFinal(input);
    }
}
