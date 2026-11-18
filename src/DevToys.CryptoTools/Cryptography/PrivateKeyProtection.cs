using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;

namespace DevToys.CryptoTools.Cryptography;

internal static class PrivateKeyProtection
{
    internal const int IterationCount = 600_000;

    internal static string Export(string privateKeyPem, string password)
    {
        ArgumentNullException.ThrowIfNull(privateKeyPem);
        ArgumentNullException.ThrowIfNull(password);
        if (password.Length == 0) return privateKeyPem;

        var fields = PemEncoding.Find(privateKeyPem);
        if (privateKeyPem[fields.Label] != "PRIVATE KEY") throw new ArgumentException(L("InvalidKey"));
        byte[] privateKeyDer = Convert.FromBase64String(privateKeyPem[fields.Base64Data]);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        byte[] derivedKey = [];
        try
        {
            _ = PrivateKeyInfo.GetInstance(privateKeyDer);
            byte[] salt = RandomNumberGenerator.GetBytes(32);
            byte[] iv = RandomNumberGenerator.GetBytes(16);
            // Use explicit UTF-8 bytes: Bouncy Castle's char[] PBES2 factory
            // performs an 8-bit password conversion, which rejects Unicode.
            derivedKey = Rfc2898DeriveBytes.Pbkdf2(passwordBytes, salt, IterationCount, HashAlgorithmName.SHA256, 32);
            using var aes = Aes.Create();
            aes.Key = derivedKey;
            byte[] ciphertext = aes.EncryptCbc(privateKeyDer, iv, PaddingMode.PKCS7);
            var parameters = new PbeS2Parameters(
                new KeyDerivationFunc(PkcsObjectIdentifiers.IdPbkdf2,
                    new Pbkdf2Params(salt, IterationCount, 32, new AlgorithmIdentifier(PkcsObjectIdentifiers.IdHmacWithSha256, DerNull.Instance))),
                new EncryptionScheme(NistObjectIdentifiers.IdAes256Cbc, new DerOctetString(iv)));
            var encrypted = new EncryptedPrivateKeyInfo(new AlgorithmIdentifier(PkcsObjectIdentifiers.IdPbeS2, parameters), ciphertext);
            return PemEncoding.WriteString("ENCRYPTED PRIVATE KEY", encrypted.GetDerEncoded());
        }
        finally
        {
            CryptographicOperations.ZeroMemory(privateKeyDer);
            CryptographicOperations.ZeroMemory(passwordBytes);
            CryptographicOperations.ZeroMemory(derivedKey);
        }
    }
}
