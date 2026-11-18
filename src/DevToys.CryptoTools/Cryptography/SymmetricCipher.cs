using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace DevToys.CryptoTools.Cryptography;

internal static class SymmetricCipher
{
    internal static int IvLength(string algorithm) => SymmetricAlgorithmCatalog.IvLength(algorithm);

    // Authenticated ciphertext includes its authentication tag at the end.
    internal static byte[] Transform(bool encrypt, string algorithm, byte[] key, byte[] iv, byte[] input,
        PaddingMode padding = PaddingMode.None, byte[]? associatedData = null)
    {
        var specification = SymmetricAlgorithmCatalog.Resolve(algorithm);
        Validate(algorithm, key, iv, input, padding, encrypt, associatedData);
        if (specification.BlockSize == 0)
            return StreamTransform(encrypt, specification, key, iv, input, associatedData);

        string engineName = specification.Algorithm == "TripleDES" ? "DESEDE" : specification.Algorithm;
        if (SymmetricAlgorithmCatalog.TagLength(algorithm) > 0)
        {
            var cipher = CipherUtilities.GetCipher(engineName + "/" + specification.Mode + "/NoPadding");
            cipher.Init(encrypt, new AeadParameters(new KeyParameter(key), SymmetricAlgorithmCatalog.TagLength(algorithm) * 8, iv, associatedData));
            return cipher.DoFinal(input);
        }

        byte[] workingInput = input;
        bool padded = specification.Mode is "ECB" or "CBC";
        if (encrypt && padded && padding != PaddingMode.None) workingInput = AddPadding(input, specification.BlockSize, padding);
        try
        {
            string modeName = specification.Mode == "CFB" ? "CFB" + specification.BlockSize * 8 : specification.Mode;
            var cipher = CipherUtilities.GetCipher(engineName + "/" + modeName + "/NoPadding");
            ICipherParameters parameters = new KeyParameter(key);
            if (iv.Length > 0) parameters = new ParametersWithIV(parameters, iv);
            cipher.Init(encrypt, parameters);
            byte[] result = cipher.DoFinal(workingInput);
            return !encrypt && padded && padding != PaddingMode.None ? RemovePadding(result, specification.BlockSize, padding) : result;
        }
        finally { if (!ReferenceEquals(workingInput, input)) CryptographicOperations.ZeroMemory(workingInput); }
    }

    private static byte[] StreamTransform(bool encrypt, SymmetricAlgorithm algorithm, byte[] key, byte[] iv, byte[] input, byte[]? associatedData)
    {
        if (algorithm.Mode == "Poly1305")
        {
            IAeadCipher cipher = algorithm.Algorithm == "XChaCha20" ? new XChaCha20Poly1305() : new Org.BouncyCastle.Crypto.Modes.ChaCha20Poly1305();
            cipher.Init(encrypt, new AeadParameters(new KeyParameter(key), 128, iv, associatedData));
            byte[] output = new byte[cipher.GetOutputSize(input.Length)];
            int written = cipher.ProcessBytes(input, 0, input.Length, output, 0);
            written += cipher.DoFinal(output, written);
            return output[..written];
        }
        IStreamCipher stream = algorithm.Algorithm switch
        {
            "ChaCha20" => new ChaCha7539Engine(),
            "XChaCha20" => new XChaCha20Engine(),
            "Salsa20" => new Salsa20Engine(),
            "XSalsa20" => new XSalsa20Engine(),
            _ => throw new ArgumentException(L("InvalidAlgorithm"))
        };
        stream.Init(encrypt, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] result = new byte[input.Length];
        stream.ProcessBytes(input, 0, input.Length, result, 0);
        return result;
    }

    private static void Validate(string algorithm, byte[] key, byte[] iv, byte[] input, PaddingMode padding, bool encrypt, byte[]? associatedData)
    {
        var specification = SymmetricAlgorithmCatalog.Resolve(algorithm);
        int length = IvLength(algorithm);
        if (!SymmetricAlgorithmCatalog.IsKeyLengthValid(algorithm, key.Length)) throw new ArgumentException(L("InvalidKeySize"));
        if (iv.Length != length) throw new ArgumentException(string.Format(System.Globalization.CultureInfo.CurrentCulture, L("InvalidIvSize"), length));
        if (!SymmetricAlgorithmCatalog.PaddingNames(algorithm).Contains(padding.ToString())) throw new ArgumentException(L("InvalidPadding"));
        int tagLength = SymmetricAlgorithmCatalog.TagLength(algorithm);
        if (!encrypt && input.Length < tagLength) throw new ArgumentException(L("InvalidCiphertext"));
        if (tagLength == 0 && associatedData is { Length: > 0 }) throw new ArgumentException(L("UnsupportedAssociatedData"));
        if (specification.Mode is "ECB" or "CBC")
        {
            if ((!encrypt || padding == PaddingMode.None) && input.Length % specification.BlockSize != 0
                || (!encrypt && padding != PaddingMode.None && padding != PaddingMode.Zeros && input.Length == 0))
                throw new ArgumentException(L("InvalidCipherLength"));
        }
    }

    private static byte[] AddPadding(byte[] input, int blockSize, PaddingMode padding)
    {
        int count = blockSize - input.Length % blockSize;
        // Zero padding does not append a block to an already aligned message.
        if (padding == PaddingMode.Zeros && count == blockSize) return input.ToArray();
        byte[] output = new byte[input.Length + count];
        input.CopyTo(output, 0);
        if (padding == PaddingMode.PKCS7) output.AsSpan(input.Length).Fill((byte)count);
        else if (padding == PaddingMode.ISO10126) RandomNumberGenerator.Fill(output.AsSpan(input.Length, count - 1));
        if (padding is PaddingMode.ANSIX923 or PaddingMode.ISO10126) output[^1] = (byte)count;
        return output;
    }

    private static byte[] RemovePadding(byte[] input, int blockSize, PaddingMode padding)
    {
        if (padding == PaddingMode.Zeros)
        {
            int end = input.Length;
            while (end > 0 && input[end - 1] == 0) end--;
            byte[] result = input[..end];
            CryptographicOperations.ZeroMemory(input);
            return result;
        }
        int count = input[^1];
        int mismatch = count is < 1 || count > blockSize ? 1 : 0;
        int checkedCount = Math.Min(count, blockSize);
        if (padding != PaddingMode.ISO10126)
        {
            for (int i = 1; i <= checkedCount; i++)
            {
                byte expected = padding == PaddingMode.PKCS7 || i == 1 ? (byte)count : (byte)0;
                mismatch |= input[^i] ^ expected;
            }
        }
        if (mismatch != 0)
        {
            CryptographicOperations.ZeroMemory(input);
            throw new CryptographicException(L("InvalidPadding"));
        }
        byte[] unpadded = input[..^count];
        CryptographicOperations.ZeroMemory(input);
        return unpadded;
    }
}
