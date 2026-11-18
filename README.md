# DevToys.CryptoTools

Cryptography extension for DevToys 2.0, targeting .NET 8 and `DevToys.Api 2.0.10-preview`.
English is the default language; Simplified Chinese follows the DevToys UI culture. Other languages fall back to English.

## Tools

| Group | Tool | Algorithms |
| --- | --- | --- |
| Generators | Key generator | RSA 2048/3072/4096; ECDSA and ECDH P-256/P-384/P-521; Ed25519/Ed448; X25519/X448; SM2; AES 128/192/256; ChaCha20; SM4 |
| Generators | Certificate generator | Self-signed X.509 and PKCS#10 CSR: RSA, ECDSA, Ed25519/Ed448, SM2 with SM3; DNS SANs |
| Cryptography / 加解密 | RSA | OAEP SHA-256/384/512, PKCS#1 v1.5 encryption; PSS and PKCS#1 v1.5 signatures with SHA-256/384/512 |
| Cryptography / 加解密 | Elliptic curve cryptography | ECDSA, Ed25519/Ed448, SM2 signing/verification; ECDH/X25519/X448 hybrid encryption; SM2 C1C3C2/C1C2C3 encryption |
| Cryptography / 加解密 | Symmetric encryption | AES-GCM/CBC, ChaCha20-Poly1305, SM4-GCM/CBC |

## Install and try

1. Open **Manage extensions** in DevToys and install `DevToys.CryptoTools.0.2.0.nupkg` from `artifacts/`.
2. Restart DevToys. Key and certificate tools appear under **Generators**; the other three tools appear under **Cryptography** (加解密 in Chinese).
3. Generate a key using the algorithm needed by your operation. Copy the public PEM key to encrypt/verify, or the private PEM key to decrypt/sign. The symmetric page defaults to **Hex** for both key and IV; choose **Base64** when pasting a key from the key generator. Text keys and IVs use their UTF-8 bytes directly, without password derivation.
4. Encryption and signing accept UTF-8 text by default. On the symmetric page, input and output are side by side and each has a **Base64 / Hex / Text (UTF-8)** selector. **Use output as input** transfers the result and switches the encodings for decryption. To verify signatures, enter the original text in **Input** and the Base64 signature in **Signature**.
5. Certificates and CSRs are PEM text. Save the certificate/request and its matching PKCS#8 private key separately. Every generation creates a new key. Self-signed certificates are intended for local development; CSRs need a CA signature.

All operations run locally. Inputs, private keys and plaintext are not logged or saved in settings. **Clear** removes the current tool's text; copied clipboard contents remain under your control.

## Formats and interoperability

- Public keys: SPKI `PUBLIC KEY` PEM. Private keys: unencrypted PKCS#8 `PRIVATE KEY` PEM. RSA additionally accepts the PEM forms supported by .NET `ImportFromPem`.
- RSA ciphertext and signatures: Base64. RSA is limited to short messages; the tool checks the selected padding's byte limit before encrypting.
- ECDSA and SM2 signatures: ASN.1 DER `(r, s)`, Base64 encoded. Ed25519 and Ed448: pure EdDSA, raw signature bytes in Base64, empty Ed448 context. ECDSA hash is SHA-256/384/512 for P-256/384/521 respectively.
- SM2: sm2p256v1 curve, SM3, UTF-8 user ID (default `1234567812345678`). Signing and verification require the same ID. Encryption uses Base64 raw C1C3C2 or C1C2C3 with an uncompressed C1 point including the `04` prefix; it does not use the hybrid JSON format.
- ECDH/XDH hybrid ciphertext: CryptoTools JSON envelope, version 1. It includes `algorithm`, `ephemeralPublicKey` (Base64 SPKI DER), `salt`, `nonce`, `tag`, and `ciphertext` (all Base64). A fresh ephemeral key, 32-byte salt and 12-byte nonce are generated per message. The raw shared secret feeds HKDF-SHA256 to derive a 32-byte AES-GCM key. Both HKDF info and GCM additional authenticated data are UTF-8 `DevToys.CryptoTools.EC.v1|` followed by the exact algorithm name. ECDH secrets are fixed-width, unsigned big-endian; XDH secrets follow RFC 7748. Tags are 16 bytes. This is a plugin-specific format, not a generic ECIES standard. It does not authenticate the sender.
- Symmetric page (v0.2.0): raw ciphertext in the selected output encoding, with a separate IV field. AES and SM4 provide GCM and CBC modes; ChaCha20 uses Poly1305. GCM/Poly1305 use 12-byte nonces and append a 16-byte tag to the ciphertext; additional authenticated data is empty. CBC uses a 16-byte IV and selectable PKCS#7 or no padding. Without padding, input must be a multiple of 16 bytes. **CBC does not authenticate ciphertext.** Binary ciphertext should use Base64 or Hex; Text output requires valid UTF-8 bytes.
- Leaving IV empty enables automatic random generation and displays the value used. Automatic IVs refresh on each encryption until you enter a manual value; **Random IV** resumes automatic generation. Decryption uses the displayed IV. Keys and IVs support independent Base64, Hex (including whitespace-separated bytes), and UTF-8 text encodings. AES keys are 16/24/32 bytes, SM4 keys 16 bytes, and ChaCha20 keys 32 bytes.
- Compatibility: the symmetric page can still decrypt v0.1.0 JSON envelopes when the matching algorithm/mode is selected. Those envelopes contain their own IV and tag and use UTF-8 `DevToys.CryptoTools.Symmetric.v1|` plus the algorithm name as additional authenticated data. New encryption produces raw ciphertext.

## Build and test

Use a .NET SDK capable of targeting .NET 8. No native dependencies are required beyond the runtime's cryptography providers.

```powershell
dotnet restore
dotnet build -c Release --no-restore
dotnet test -c Release --no-build
dotnet pack src/DevToys.CryptoTools -c Release --no-build -o artifacts
pwsh -File scripts/Verify-Package.ps1 -PackagePath artifacts/DevToys.CryptoTools.0.2.0.nupkg
```

Tests cover key import, certificate/CSR signatures, algorithm round trips, invalid key types, message limits, tampering, SM2 IDs, RFC 8032 and NIST vectors, MEF discovery, language fallback, symmetric page encodings, IV generation and button workflows. GitHub Actions runs the suite on Windows, Linux and macOS.

The package bundles Bouncy Castle and its license plus the Chinese satellite assembly. DevToys supplies its API and framework dependencies; the package does not require a NuGet dependency restore when installed.

## Project structure

- `src/DevToys.CryptoTools/Cryptography`: cryptographic services.
- `src/DevToys.CryptoTools/Tools`: five MEF-exported GUI tools.
- `src/DevToys.CryptoTools/Localization`: English resources and `Strings.zh-Hans.resx`.
- `tests/DevToys.CryptoTools.Tests`: algorithm and plugin integration tests.

New languages can be added as `Strings.<culture>.resx`, using the English resource keys. Host language changes take effect after recreating the tools/restarting DevToys.

Built using the [DevToys extension API](https://devtoys.app/doc/articles/extension-development/getting-started/create-an-extension.html) and [Bouncy Castle for C#](https://www.bouncycastle.org/download/bouncy-castle-c/).
