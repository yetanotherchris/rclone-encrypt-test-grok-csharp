using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace RcloneEncrypt;

/// <summary>
/// Rclone-compatible cipher (standard name encryption + XSalsa20Poly1305 file content).
/// </summary>
public sealed class RcloneCipher : IDisposable
{
    private const string FileMagic = "RCLONE\x00\x00";
    private const int FileMagicSize = 8;
    private const int FileNonceSize = 24;
    private const int FileHeaderSize = FileMagicSize + FileNonceSize;
    private const int BlockDataSize = 64 * 1024;
    private const int BlockHeaderSize = 16;
    private const int BlockSize = BlockHeaderSize + BlockDataSize;
    private const int NameBlockSize = 16;

    private static readonly byte[] DefaultSalt = new byte[] { 0xA8, 0x0D, 0xF4, 0x3A, 0x8F, 0xBD, 0x03, 0x08, 0xA7, 0xCA, 0xB8, 0x3E, 0x58, 0x1F, 0x86, 0xB1 };

    public enum NameMode { Standard, Off }
    public enum NameEncoding { Base32, Base64 }

    private readonly byte[] _dataKey = new byte[32];
    private readonly byte[] _nameKey = new byte[32];
    private readonly byte[] _nameTweak = new byte[NameBlockSize];
    private readonly Aes _nameAes;
    private readonly NameMode _mode;
    private readonly NameEncoding _encoding;
    private bool _disposed;

    public RcloneCipher(string password, string? salt, NameMode mode = NameMode.Standard, NameEncoding encoding = NameEncoding.Base32)
    {
        _mode = mode;
        _encoding = encoding;
        DeriveKeys(password, salt);
        _nameAes = Aes.Create();
        _nameAes.KeySize = 256;
        _nameAes.Mode = CipherMode.ECB;
        _nameAes.Padding = PaddingMode.None;
        _nameAes.Key = _nameKey;
    }

    private void DeriveKeys(string password, string? salt)
    {
        byte[] saltBytes = string.IsNullOrEmpty(salt) ? DefaultSalt : Encoding.UTF8.GetBytes(salt);
        byte[] pw = string.IsNullOrEmpty(password) ? Array.Empty<byte>() : Encoding.UTF8.GetBytes(password);
        const int keySize = 80;
        byte[] keyMaterial = pw.Length == 0 ? new byte[keySize] : Org.BouncyCastle.Crypto.Generators.SCrypt.Generate(pw, saltBytes, 16384, 8, 1, keySize);
        Buffer.BlockCopy(keyMaterial, 0, _dataKey, 0, 32);
        Buffer.BlockCopy(keyMaterial, 32, _nameKey, 0, 32);
        Buffer.BlockCopy(keyMaterial, 64, _nameTweak, 0, 16);
    }

    public string EncryptFileName(string name)
    {
        if (_mode == NameMode.Off) return name + ".bin";
        var segments = name.Split('/');
        for (int i = 0; i < segments.Length; i++)
        {
            if (segments[i].Length == 0) continue;
            segments[i] = EncryptSegment(segments[i]);
        }
        return string.Join('/', segments);
    }

    public string DecryptFileName(string name)
    {
        if (_mode == NameMode.Off)
        {
            if (name.EndsWith(".bin")) return name[..^4];
            return name;
        }
        var segments = name.Split('/');
        for (int i = 0; i < segments.Length; i++)
        {
            if (segments[i].Length == 0) continue;
            segments[i] = DecryptSegment(segments[i]);
        }
        return string.Join('/', segments);
    }

    private string EncryptSegment(string plain)
    {
        byte[] padded = Pkcs7.Pad(NameBlockSize, Encoding.UTF8.GetBytes(plain));
        byte[] cipher = Eme.Transform(_nameTweak, padded, true, _nameAes);
        return EncodeName(cipher);
    }

    private string DecryptSegment(string enc)
    {
        byte[] raw = DecodeName(enc);
        if (raw.Length % NameBlockSize != 0) throw new CryptographicException("not multiple of blocksize");
        byte[] padded = Eme.Transform(_nameTweak, raw, false, _nameAes);
        byte[] plain = Pkcs7.Unpad(NameBlockSize, padded);
        return Encoding.UTF8.GetString(plain);
    }

    private string EncodeName(byte[] data) => _encoding == NameEncoding.Base64 ? Base64UrlEncode(data) : ToBase32HexLowerNoPad(data);
    private byte[] DecodeName(string s) => _encoding == NameEncoding.Base64 ? Base64UrlDecode(s) : FromBase32HexLowerNoPad(s);

    private static readonly char[] B32 = "0123456789abcdefghijklmnopqrstuv".ToCharArray();

    private static string ToBase32HexLowerNoPad(byte[] input)
    {
        var bits = new StringBuilder();
        foreach (byte b in input) bits.Append(Convert.ToString(b, 2).PadLeft(8, '0'));
        int pad = (5 - (bits.Length % 5)) % 5; bits.Append('0', pad);
        var sb = new StringBuilder();
        for (int i = 0; i < bits.Length; i += 5)
        {
            int val = Convert.ToInt32(bits.ToString(i, 5), 2);
            sb.Append(B32[val]);
        }
        return sb.ToString().ToLowerInvariant();
    }

    private static byte[] FromBase32HexLowerNoPad(string input)
    {
        var map = new Dictionary<char, int>(); for (int i = 0; i < B32.Length; i++) map[B32[i]] = i;
        var bits = new StringBuilder();
        foreach (char c in input.ToLowerInvariant())
        {
            if (!map.TryGetValue(c, out int v)) throw new FormatException("bad base32");
            bits.Append(Convert.ToString(v, 2).PadLeft(5, '0'));
        }
        int extra = bits.Length % 8; if (extra != 0) bits.Remove(bits.Length - extra, extra);
        var bytes = new List<byte>();
        for (int i = 0; i < bits.Length; i += 8) bytes.Add(Convert.ToByte(bits.ToString(i, 8), 2));
        return bytes.ToArray();
    }

    private static string Base64UrlEncode(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    private static byte[] Base64UrlDecode(string s)
    {
        string t = s.Replace('-', '+').Replace('_', '/');
        switch (t.Length % 4) { case 2: t += "=="; break; case 3: t += "="; break; }
        return Convert.FromBase64String(t);
    }

    public byte[] EncryptData(byte[] plaintext)
    {
        byte[] nonce = new byte[FileNonceSize];
        RandomNumberGenerator.Fill(nonce);
        var header = new byte[FileHeaderSize];
        Encoding.ASCII.GetBytes(FileMagic).CopyTo(header, 0);
        nonce.CopyTo(header, FileMagicSize);
        var chunks = new List<byte>(header);
        int offset = 0;
        while (offset < plaintext.Length)
        {
            int size = Math.Min(BlockDataSize, plaintext.Length - offset);
            var plainChunk = new byte[size];
            Buffer.BlockCopy(plaintext, offset, plainChunk, 0, size);
            var box = XSalsa20Poly1305.Seal(_dataKey, nonce, plainChunk);
            chunks.AddRange(box);
            IncrementNonce(nonce);
            offset += size;
        }
        return chunks.ToArray();
    }

    public byte[] DecryptData(byte[] ciphertext)
    {
        if (ciphertext.Length < FileHeaderSize) throw new CryptographicException("file too short");
        if (Encoding.ASCII.GetString(ciphertext, 0, FileMagicSize) != FileMagic) throw new CryptographicException("bad magic");
        byte[] nonce = new byte[FileNonceSize];
        Buffer.BlockCopy(ciphertext, FileMagicSize, nonce, 0, FileNonceSize);
        var output = new List<byte>();
        int offset = FileHeaderSize;
        while (offset < ciphertext.Length)
        {
            if (offset + BlockHeaderSize > ciphertext.Length) throw new CryptographicException("truncated block header");
            int remaining = ciphertext.Length - offset;
            int cipherLen = Math.Min(BlockSize, remaining);
            var block = new byte[cipherLen];
            Buffer.BlockCopy(ciphertext, offset, block, 0, cipherLen);
            try
            {
                var plain = XSalsa20Poly1305.Open(_dataKey, nonce, block);
                output.AddRange(plain);
            }
            catch { throw new CryptographicException("bad password or corrupt block"); }
            IncrementNonce(nonce);
            offset += cipherLen;
        }
        return output.ToArray();
    }

    private static void IncrementNonce(byte[] n) { for (int i = 0; i < n.Length; i++) { if (++n[i] != 0) break; } }

    public void Dispose()
    {
        if (_disposed) return;
        _nameAes.Dispose();
        _disposed = true;
    }
}

/// <summary>
/// XSalsa20Poly1305 secretbox (tag || ct) compatible with rclone using BouncyCastle.
/// </summary>
file static class XSalsa20Poly1305
{
    private const int KeySize = 32;
    private const int NonceSize = 24;
    private const int TagSize = 16;

    public static byte[] Seal(byte[] key, byte[] nonce, byte[] plaintext)
    {
        if (key.Length != KeySize || nonce.Length != NonceSize) throw new ArgumentException("bad key/nonce");
        var engine = new XSalsa20Engine();
        engine.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        byte[] block0 = new byte[64];
        engine.ProcessBytes(new byte[64], 0, 64, block0, 0);
        byte[] polyKey = new byte[32]; Buffer.BlockCopy(block0, 0, polyKey, 0, 32);
        byte[] ct = new byte[plaintext.Length];
        int n = Math.Min(32, plaintext.Length);
        for (int i = 0; i < n; i++) ct[i] = (byte)(plaintext[i] ^ block0[32 + i]);
        if (plaintext.Length > 32) engine.ProcessBytes(plaintext, 32, plaintext.Length - 32, ct, 32);
        var poly = new Poly1305();
        poly.Init(new KeyParameter(polyKey));
        poly.BlockUpdate(ct, 0, ct.Length);
        byte[] tag = new byte[TagSize]; poly.DoFinal(tag, 0);
        byte[] result = new byte[TagSize + ct.Length];
        Buffer.BlockCopy(tag, 0, result, 0, TagSize);
        Buffer.BlockCopy(ct, 0, result, TagSize, ct.Length);
        return result;
    }

    public static byte[] Open(byte[] key, byte[] nonce, byte[] tagged)
    {
        if (key.Length != KeySize || nonce.Length != NonceSize) throw new ArgumentException("bad key/nonce");
        if (tagged.Length < TagSize) throw new CryptographicException("ciphertext too short");
        byte[] tag = new byte[TagSize]; byte[] ct = new byte[tagged.Length - TagSize];
        Buffer.BlockCopy(tagged, 0, tag, 0, TagSize);
        Buffer.BlockCopy(tagged, TagSize, ct, 0, ct.Length);
        var engine = new XSalsa20Engine();
        engine.Init(true, new ParametersWithIV(new KeyParameter(key), nonce));
        byte[] block0 = new byte[64];
        engine.ProcessBytes(new byte[64], 0, 64, block0, 0);
        byte[] polyKey = new byte[32]; Buffer.BlockCopy(block0, 0, polyKey, 0, 32);
        var poly = new Poly1305();
        poly.Init(new KeyParameter(polyKey));
        poly.BlockUpdate(ct, 0, ct.Length);
        byte[] computed = new byte[TagSize]; poly.DoFinal(computed, 0);
        if (!CryptographicOperations.FixedTimeEquals(tag, computed)) throw new CryptographicException("authentication failed");
        byte[] pt = new byte[ct.Length];
        int n = Math.Min(32, ct.Length);
        for (int i = 0; i < n; i++) pt[i] = (byte)(ct[i] ^ block0[32 + i]);
        if (ct.Length > 32) engine.ProcessBytes(ct, 32, ct.Length - 32, pt, 32);
        return pt;
    }
}
