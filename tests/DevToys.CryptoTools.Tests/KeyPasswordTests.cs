using System.Security.Cryptography;
using DevToys.CryptoTools.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Pkcs;

namespace DevToys.CryptoTools.Tests;

public class KeyPasswordTests
{
    [Theory]
    [InlineData("RSA-2048")]
    [InlineData("ECDSA-P256")]
    [InlineData("ECDSA-secp256k1")]
    [InlineData("ECDH-brainpoolP512r1")]
    [InlineData("Ed25519")]
    [InlineData("Ed448")]
    [InlineData("X25519")]
    [InlineData("X448")]
    [InlineData("SM2")]
    public void PasswordProtectedExportPreservesEveryKeyFamily(string algorithm)
    {
        var keys = KeyGenerator.Generate(algorithm);
        string encrypted = PrivateKeyProtection.Export(keys.PrivateKey, "test export password");
        Assert.StartsWith("-----BEGIN ENCRYPTED PRIVATE KEY-----", encrypted);
        var decrypted = PrivateKeyInfoFactory.CreatePrivateKeyInfo("test export password".ToCharArray(), ReadEncrypted(encrypted));
        Assert.Equal(ReadDer(keys.PrivateKey), decrypted.GetDerEncoded());
        Assert.Contains("BEGIN PUBLIC KEY", keys.PublicKey);
    }

    [Fact]
    public void EmptyPasswordKeepsTheOriginalUnencryptedPem()
    {
        string privateKey = KeyGenerator.Generate("Ed25519").PrivateKey;
        Assert.Equal(privateKey, PrivateKeyProtection.Export(privateKey, ""));
    }

    [Fact]
    public void Pbes2ParametersAreExplicitAndSaltAndIvAreRandom()
    {
        string privateKey = KeyGenerator.Generate("Ed25519").PrivateKey;
        var first = ReadEncrypted(PrivateKeyProtection.Export(privateKey, "password"));
        var second = ReadEncrypted(PrivateKeyProtection.Export(privateKey, "password"));
        var firstParameters = CheckParameters(first);
        var secondParameters = CheckParameters(second);
        Assert.NotEqual(firstParameters.Salt, secondParameters.Salt);
        Assert.NotEqual(firstParameters.Iv, secondParameters.Iv);
        Assert.NotEqual(first.EncryptedData.GetOctets(), second.EncryptedData.GetOctets());
    }

    [Fact]
    public void UnicodePasswordInteroperatesWithDotNetAndRejectsAWrongPassword()
    {
        const string password = "证书🔐 Pässwörd";
        var keys = KeyGenerator.Generate("RSA-2048");
        string encrypted = PrivateKeyProtection.Export(keys.PrivateKey, password);
        using var rsa = RSA.Create();
        rsa.ImportFromEncryptedPem(encrypted, password);
        Assert.Equal(keys.PublicKey, rsa.ExportSubjectPublicKeyInfoPem());
        Assert.Throws<CryptographicException>(() => rsa.ImportFromEncryptedPem(encrypted, "wrong password"));
    }

    private static (byte[] Salt, byte[] Iv) CheckParameters(EncryptedPrivateKeyInfo encrypted)
    {
        Assert.Equal(PkcsObjectIdentifiers.IdPbeS2, encrypted.EncryptionAlgorithm.Algorithm);
        var pbes2 = PbeS2Parameters.GetInstance(encrypted.EncryptionAlgorithm.Parameters);
        Assert.Equal(PkcsObjectIdentifiers.IdPbkdf2, pbes2.KeyDerivationFunc.Algorithm);
        var kdf = Pbkdf2Params.GetInstance(pbes2.KeyDerivationFunc.Parameters);
        Assert.Equal(600_000, kdf.IterationCount.IntValueExact);
        Assert.Equal(32, kdf.KeyLength.IntValueExact);
        Assert.Equal(PkcsObjectIdentifiers.IdHmacWithSha256, kdf.Prf.Algorithm);
        byte[] salt = kdf.Salt.GetOctets();
        Assert.Equal(32, salt.Length);
        Assert.Equal(NistObjectIdentifiers.IdAes256Cbc, pbes2.EncryptionScheme.Algorithm);
        byte[] iv = Asn1OctetString.GetInstance(pbes2.EncryptionScheme.Parameters).GetOctets();
        Assert.Equal(16, iv.Length);
        return (salt, iv);
    }

    private static byte[] ReadDer(string pem)
    {
        var fields = PemEncoding.Find(pem);
        return Convert.FromBase64String(pem[fields.Base64Data]);
    }
    private static EncryptedPrivateKeyInfo ReadEncrypted(string pem) => EncryptedPrivateKeyInfo.GetInstance(ReadDer(pem));
}
