using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace SshKeyNinja;

/// <summary>
/// Serializes Ed25519 key pairs into OpenSSH format (openssh-key-v1),
/// with optional AES-256-CTR encryption via bcrypt_pbkdf.
/// </summary>
internal static class OpenSshKeyWriter
{
    private static readonly byte[] AuthMagic = "openssh-key-v1\0"u8.ToArray();
    private const int BcryptRounds = 16;
    private const int SaltLength = 16;
    private const int AesKeyLength = 32;
    private const int AesIvLength = 16;
    private const int CipherBlockSize = 16;

    public static string FormatPrivateKey(
        Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters privateKey,
        Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters publicKey,
        string comment,
        string? passphrase = null)
    {
        bool encrypt = !string.IsNullOrEmpty(passphrase);

        byte[] publicKeyBlob = BuildPublicKeyBlob(publicKey);
        byte[] privateSectionPlain = BuildPrivateSection(privateKey, publicKey, comment, encrypt ? CipherBlockSize : 8);

        using var outer = new MemoryStream();

        outer.Write(AuthMagic);

        if (encrypt)
        {
            byte[] salt = RandomNumberGenerator.GetBytes(SaltLength);
            byte[] derived = BcryptPbkdf.DeriveKey(
                Encoding.UTF8.GetBytes(passphrase!), salt, BcryptRounds,
                AesKeyLength + AesIvLength);

            byte[] aesKey = derived[..AesKeyLength];
            byte[] aesIv = derived[AesKeyLength..];

            byte[] encryptedSection = EncryptAes256Ctr(privateSectionPlain, aesKey, aesIv);

            WriteSshString(outer, "aes256-ctr");
            WriteSshString(outer, "bcrypt");

            using var kdfOpts = new MemoryStream();
            WriteSshBytes(kdfOpts, salt);
            WriteBigEndianU32(kdfOpts, (uint)BcryptRounds);
            WriteSshBytes(outer, kdfOpts.ToArray());

            WriteBigEndianU32(outer, 1);
            WriteSshBytes(outer, publicKeyBlob);
            WriteSshBytes(outer, encryptedSection);
        }
        else
        {
            WriteSshString(outer, "none");
            WriteSshString(outer, "none");
            WriteSshString(outer, "");

            WriteBigEndianU32(outer, 1);
            WriteSshBytes(outer, publicKeyBlob);
            WriteSshBytes(outer, privateSectionPlain);
        }

        var sb = new StringBuilder();
        sb.Append("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        string base64 = Convert.ToBase64String(outer.ToArray());
        for (int i = 0; i < base64.Length; i += 70)
            sb.Append(base64.AsSpan(i, Math.Min(70, base64.Length - i))).Append('\n');
        sb.Append("-----END OPENSSH PRIVATE KEY-----\n");

        return sb.ToString();
    }

    public static string FormatPublicKey(
        Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters publicKey,
        string comment)
    {
        byte[] blob = BuildPublicKeyBlob(publicKey);
        return $"ssh-ed25519 {Convert.ToBase64String(blob)} {comment}";
    }

    public static string ComputeFingerprint(
        Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters publicKey)
    {
        byte[] blob = BuildPublicKeyBlob(publicKey);
        byte[] hash = SHA256.HashData(blob);
        return Convert.ToBase64String(hash).TrimEnd('=');
    }

    private static byte[] BuildPublicKeyBlob(
        Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters publicKey)
    {
        using var ms = new MemoryStream();
        WriteSshString(ms, "ssh-ed25519");
        WriteSshBytes(ms, publicKey.GetEncoded());
        return ms.ToArray();
    }

    private static byte[] BuildPrivateSection(
        Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters privateKey,
        Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters publicKey,
        string comment,
        int blockSize)
    {
        uint checkint = (uint)(RandomNumberGenerator.GetInt32(int.MaxValue));

        using var section = new MemoryStream();
        WriteBigEndianU32(section, checkint);
        WriteBigEndianU32(section, checkint);

        WriteSshString(section, "ssh-ed25519");
        WriteSshBytes(section, publicKey.GetEncoded());

        byte[] privEncoded = privateKey.GetEncoded();
        byte[] pubEncoded = publicKey.GetEncoded();
        byte[] combined = new byte[privEncoded.Length + pubEncoded.Length];
        Buffer.BlockCopy(privEncoded, 0, combined, 0, privEncoded.Length);
        Buffer.BlockCopy(pubEncoded, 0, combined, privEncoded.Length, pubEncoded.Length);
        WriteSshBytes(section, combined);

        WriteSshString(section, comment);

        int padLen = blockSize - ((int)section.Length % blockSize);
        if (padLen == blockSize) padLen = 0;
        for (int i = 1; i <= padLen; i++)
            section.WriteByte((byte)(i & 0xFF));

        return section.ToArray();
    }

    private static byte[] EncryptAes256Ctr(byte[] plaintext, byte[] key, byte[] iv)
    {
        var cipher = new SicBlockCipher(new AesEngine());
        cipher.Init(true, new ParametersWithIV(new KeyParameter(key), iv));

        byte[] output = new byte[plaintext.Length];
        int blockSize = cipher.GetBlockSize();

        for (int offset = 0; offset < plaintext.Length; offset += blockSize)
        {
            int remaining = Math.Min(blockSize, plaintext.Length - offset);
            if (remaining == blockSize)
            {
                cipher.ProcessBlock(plaintext, offset, output, offset);
            }
            else
            {
                byte[] block = new byte[blockSize];
                Buffer.BlockCopy(plaintext, offset, block, 0, remaining);
                byte[] encBlock = new byte[blockSize];
                cipher.ProcessBlock(block, 0, encBlock, 0);
                Buffer.BlockCopy(encBlock, 0, output, offset, remaining);
            }
        }

        return output;
    }

    private static void WriteSshString(Stream stream, string value)
    {
        byte[] bytes = Encoding.UTF8.GetBytes(value);
        WriteSshBytes(stream, bytes);
    }

    private static void WriteSshBytes(Stream stream, byte[] data)
    {
        WriteBigEndianU32(stream, (uint)data.Length);
        stream.Write(data);
    }

    private static void WriteBigEndianU32(Stream stream, uint value)
    {
        stream.WriteByte((byte)((value >> 24) & 0xFF));
        stream.WriteByte((byte)((value >> 16) & 0xFF));
        stream.WriteByte((byte)((value >> 8) & 0xFF));
        stream.WriteByte((byte)(value & 0xFF));
    }
}
