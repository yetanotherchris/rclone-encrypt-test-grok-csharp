using System.Security.Cryptography;

namespace RcloneEncrypt;

/// <summary>
/// EME (ECB-Mix-ECB) port matching rclone/eme semantics.
/// L-table always uses forward AES encrypt.
/// </summary>
internal static class Eme
{
    private const int BlockSize = 16;

    public static byte[] Transform(byte[] tweak, byte[] input, bool encrypt, Aes aes)
    {
        if (aes.BlockSize != 128) throw new InvalidOperationException("AES block 128");
        if (tweak.Length != BlockSize) throw new ArgumentException("tweak");
        if (input.Length % BlockSize != 0 || input.Length == 0) throw new ArgumentException("input");
        int m = input.Length / BlockSize;
        if (m < 1 || m > 128) throw new ArgumentException("blocks");

        byte[][] LTable = TabulateL(aes, m);

        byte[] C = new byte[input.Length];
        byte[] PPj = new byte[BlockSize];
        for (int j = 0; j < m; j++)
        {
            Xor(PPj, input, j * BlockSize, LTable[j], 0);
            Block(aes, PPj, C, j * BlockSize, encrypt);
        }

        byte[] MP = new byte[BlockSize];
        Xor(MP, C, 0, tweak, 0);
        for (int j = 1; j < m; j++) XorAccum(MP, C, j * BlockSize);

        byte[] MC = new byte[BlockSize];
        Block(aes, MP, MC, 0, encrypt);

        byte[] M = new byte[BlockSize];
        Xor(M, MP, 0, MC, 0);

        byte[] CCCj = new byte[BlockSize];
        for (int j = 1; j < m; j++)
        {
            MultByTwo(M, M);
            Xor(CCCj, C, j * BlockSize, M, 0);
            Buffer.BlockCopy(CCCj, 0, C, j * BlockSize, BlockSize);
        }

        byte[] CCC1 = new byte[BlockSize];
        Xor(CCC1, MC, 0, tweak, 0);
        for (int j = 1; j < m; j++) XorAccum(CCC1, C, j * BlockSize);
        Buffer.BlockCopy(CCC1, 0, C, 0, BlockSize);

        for (int j = 0; j < m; j++)
        {
            byte[] tmp = new byte[BlockSize];
            Buffer.BlockCopy(C, j * BlockSize, tmp, 0, BlockSize);
            Block(aes, tmp, C, j * BlockSize, encrypt);
            Xor(C.AsSpan(j * BlockSize, BlockSize), LTable[j]);
        }
        return C;
    }

    private static byte[][] TabulateL(Aes bc, int m)
    {
        byte[] Li = new byte[BlockSize];
        byte[] eZero = new byte[BlockSize];
        Block(bc, eZero, Li, 0, true);
        MultByTwo(Li, Li);

        var table = new byte[m][];
        for (int i = 0; i < m; i++)
        {
            table[i] = new byte[BlockSize];
            Buffer.BlockCopy(Li, 0, table[i], 0, BlockSize);
            MultByTwo(Li, Li);
        }
        return table;
    }

    private static void MultByTwo(byte[] x, byte[] y)
    {
        byte carry = (byte)((y[15] >> 7) & 1);
        x[0] = (byte)((y[0] << 1) ^ (135 & (byte)(-carry)));
        for (int j = 1; j < 16; j++)
        {
            carry = (byte)((y[j - 1] >> 7) & 1);
            x[j] = (byte)((y[j] << 1) | carry);
        }
    }

    private static void Xor(byte[] dst, byte[] src, int soff, byte[] x, int xoff)
    {
        for (int i = 0; i < BlockSize; i++) dst[i] = (byte)(src[soff + i] ^ x[xoff + i]);
    }

    private static void Xor(Span<byte> dst, byte[] x)
    {
        for (int i = 0; i < BlockSize; i++) dst[i] ^= x[i];
    }

    private static void XorAccum(byte[] acc, byte[] src, int soff)
    {
        for (int i = 0; i < BlockSize; i++) acc[i] ^= src[soff + i];
    }

    private static void Block(Aes aes, byte[] src, byte[] dst, int doff, bool encrypt)
    {
        using var t = encrypt ? aes.CreateEncryptor() : aes.CreateDecryptor();
        t.TransformBlock(src, 0, BlockSize, dst, doff);
    }
}
