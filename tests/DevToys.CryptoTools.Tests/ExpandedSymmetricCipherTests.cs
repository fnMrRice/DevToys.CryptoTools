using System.Security.Cryptography;
using System.Text;
using DevToys.CryptoTools.Cryptography;

namespace DevToys.CryptoTools.Tests;

public class ExpandedSymmetricCipherTests
{
    public static IEnumerable<object[]> Combinations => SymmetricAlgorithmCatalog.Algorithms.SelectMany(algorithm =>
        SymmetricAlgorithmCatalog.Modes(algorithm).SelectMany(mode =>
            SymmetricAlgorithmCatalog.PaddingNames(algorithm + "-" + mode).Select(padding => new object[] { algorithm + "-" + mode, padding })));

    public static IEnumerable<object[]> AuthenticatedCombinations => SymmetricAlgorithmCatalog.Algorithms.SelectMany(algorithm =>
        SymmetricAlgorithmCatalog.Modes(algorithm).Select(mode => algorithm + "-" + mode)
            .Where(full => SymmetricAlgorithmCatalog.TagLength(full) > 0).Select(full => new object[] { full }));

    [Theory]
    [MemberData(nameof(Combinations))]
    public void EveryAdvertisedCombinationRoundTripsEmptyAndBinaryMessages(string full, string paddingName)
    {
        var specification = SymmetricAlgorithmCatalog.Resolve(full);
        var padding = Enum.Parse<PaddingMode>(paddingName);
        byte[] key = RandomNumberGenerator.GetBytes(SymmetricAlgorithmCatalog.DefaultKeyLength(specification.Algorithm));
        byte[] iv = RandomNumberGenerator.GetBytes(SymmetricCipher.IvLength(full));
        bool aligned = specification.Mode is "ECB" or "CBC" && padding == PaddingMode.None;
        int[] sizes = aligned ? [0, specification.BlockSize, specification.BlockSize * 3] : [0, 1, 31, 513];
        foreach (int size in sizes)
        {
            byte[] plaintext = Enumerable.Range(0, size).Select(i => (byte)(i % 255 + 1)).ToArray();
            byte[] encrypted = SymmetricCipher.Transform(true, full, key, iv, plaintext, padding);
            Assert.Equal(plaintext, SymmetricCipher.Transform(false, full, key, iv, encrypted, padding));
            if (SymmetricAlgorithmCatalog.TagLength(full) > 0) Assert.Equal(size + SymmetricAlgorithmCatalog.TagLength(full), encrypted.Length);
        }
    }

    [Theory]
    [MemberData(nameof(AuthenticatedCombinations))]
    public void EveryAuthenticatedModeRejectsModifiedCiphertextKeyNonceAndAad(string full)
    {
        var specification = SymmetricAlgorithmCatalog.Resolve(full);
        byte[] key = RandomNumberGenerator.GetBytes(SymmetricAlgorithmCatalog.DefaultKeyLength(specification.Algorithm));
        byte[] iv = RandomNumberGenerator.GetBytes(SymmetricCipher.IvLength(full));
        byte[] plaintext = Encoding.UTF8.GetBytes("你好 🔑 message");
        byte[] aad = Encoding.UTF8.GetBytes("header");
        byte[] encrypted = SymmetricCipher.Transform(true, full, key, iv, plaintext, associatedData: aad);
        Assert.Equal(plaintext, SymmetricCipher.Transform(false, full, key, iv, encrypted, associatedData: aad));
        byte[] changed = encrypted.ToArray(); changed[^1] ^= 1;
        Assert.ThrowsAny<Exception>(() => SymmetricCipher.Transform(false, full, key, iv, changed, associatedData: aad));
        byte[] wrongKey = key.ToArray(); wrongKey[0] ^= 2;
        Assert.ThrowsAny<Exception>(() => SymmetricCipher.Transform(false, full, wrongKey, iv, encrypted, associatedData: aad));
        byte[] wrongIv = iv.ToArray(); wrongIv[0] ^= 1;
        Assert.ThrowsAny<Exception>(() => SymmetricCipher.Transform(false, full, key, wrongIv, encrypted, associatedData: aad));
        Assert.ThrowsAny<Exception>(() => SymmetricCipher.Transform(false, full, key, iv, encrypted, associatedData: [1]));
    }

    [Theory]
    [InlineData("AES-CFB", "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a", "3b3fd92eb72dad20333449f8e83cfb4a")]
    [InlineData("AES-OFB", "2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090a0b0c0d0e0f", "6bc1bee22e409f96e93d7e117393172a", "3b3fd92eb72dad20333449f8e83cfb4a")]
    [InlineData("SM4-ECB", "0123456789abcdeffedcba9876543210", "", "0123456789abcdeffedcba9876543210", "681edf34d206965e86b3e94f536e4246")]
    [InlineData("Blowfish-ECB", "0000000000000000", "", "0000000000000000", "4ef997456198dd78")]
    [InlineData("CAST5-ECB", "0123456712345678234567893456789a", "", "0123456789abcdef", "238b4fe5847e44b2")]
    [InlineData("DES-ECB", "133457799bbcdff1", "", "0123456789abcdef", "85e813540f0ab405")]
    [InlineData("RC2-ECB", "ffffffffffffffff", "", "ffffffffffffffff", "278b27e42e2f0d49")]
    public void MatchesPublishedBlockCipherVectors(string full, string key, string iv, string plaintext, string expected)
    {
        byte[] encrypted = SymmetricCipher.Transform(true, full, Convert.FromHexString(key), Convert.FromHexString(iv), Convert.FromHexString(plaintext));
        Assert.Equal(expected, Convert.ToHexString(encrypted).ToLowerInvariant());
    }

    [Fact]
    public void AesCtrMatchesNistSp80038AVector()
    {
        byte[] key = Convert.FromHexString("2b7e151628aed2a6abf7158809cf4f3c");
        byte[] iv = Convert.FromHexString("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
        byte[] plaintext = Convert.FromHexString("6bc1bee22e409f96e93d7e117393172a");
        Assert.Equal("874d6191b620e3261bef6864990db6ce", Convert.ToHexString(SymmetricCipher.Transform(true, "AES-CTR", key, iv, plaintext)).ToLowerInvariant());
    }

    [Fact]
    public void ChaCha20IetfStartsWithRfc8439ZeroCounterVector()
    {
        Assert.Equal("76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
            Convert.ToHexString(SymmetricCipher.Transform(true, "ChaCha20-IETF", new byte[32], new byte[12], new byte[64])).ToLowerInvariant());
    }

    [Fact]
    public void ChaChaPoly1305MatchesRuntimeImplementation()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] plaintext = Encoding.UTF8.GetBytes("cross-provider test 🔑");
        byte[] encrypted = new byte[plaintext.Length]; byte[] tag = new byte[16];
        using var runtime = new ChaCha20Poly1305(key);
        runtime.Encrypt(nonce, plaintext, encrypted, tag, new byte[] { 1, 2, 3 });
        Assert.Equal([.. encrypted, .. tag], SymmetricCipher.Transform(true, "ChaCha20-Poly1305", key, nonce, plaintext, associatedData: [1, 2, 3]));
    }

    [Theory]
    [InlineData("AES-CBC")]
    [InlineData("Blowfish-CBC")]
    public void StandardPaddingsRejectCorruptionAndZeroPaddingTrimsTrailingZeros(string algorithm)
    {
        var specification = SymmetricAlgorithmCatalog.Resolve(algorithm);
        byte[] key = new byte[16]; byte[] iv = new byte[specification.BlockSize];
        foreach (var padding in new[] { PaddingMode.PKCS7, PaddingMode.ANSIX923, PaddingMode.ISO10126 })
        {
            byte[] ciphertext = SymmetricCipher.Transform(true, algorithm, key, iv, [1], padding);
            byte[] invalid = new byte[specification.BlockSize]; invalid[^1] = 0;
            byte[] encryptedInvalid = SymmetricCipher.Transform(true, algorithm, key, iv, invalid);
            Assert.Throws<CryptographicException>(() => SymmetricCipher.Transform(false, algorithm, key, iv, encryptedInvalid, padding));
            Assert.Equal(new byte[] { 1 }, SymmetricCipher.Transform(false, algorithm, key, iv, ciphertext, padding));
        }
        byte[] zeroPadded = SymmetricCipher.Transform(true, algorithm, key, iv, [1, 2, 0], PaddingMode.Zeros);
        Assert.Equal(new byte[] { 1, 2 }, SymmetricCipher.Transform(false, algorithm, key, iv, zeroPadded, PaddingMode.Zeros));
    }

    [Theory]
    [InlineData("AES", 15, false)]
    [InlineData("AES", 24, true)]
    [InlineData("SM4", 32, false)]
    [InlineData("Blowfish", 4, true)]
    [InlineData("Blowfish", 57, false)]
    [InlineData("CAST5", 5, true)]
    [InlineData("DES", 8, true)]
    [InlineData("TripleDES", 16, true)]
    [InlineData("TripleDES", 24, true)]
    [InlineData("RC2", 1, true)]
    [InlineData("RC2", 129, false)]
    [InlineData("Salsa20", 16, true)]
    [InlineData("XSalsa20", 16, false)]
    public void KeyLengthCatalogEnforcesAlgorithmBounds(string algorithm, int size, bool valid)
    {
        Assert.Equal(valid, SymmetricAlgorithmCatalog.IsKeyLengthValid(algorithm + "-" + SymmetricAlgorithmCatalog.Modes(algorithm)[0], size));
    }
}
