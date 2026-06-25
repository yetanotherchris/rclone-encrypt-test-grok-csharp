using System.Security.Cryptography;

namespace RcloneEncrypt;

internal static class Pkcs7
{
    public static byte[] Pad(int blockSize, byte[] data)
    {
        int padding = blockSize - (data.Length % blockSize);
        if (padding == 0) padding = blockSize;
        byte[] result = new byte[data.Length + padding];
        Buffer.BlockCopy(data, 0, result, 0, data.Length);
        for (int i = data.Length; i < result.Length; i++) result[i] = (byte)padding;
        return result;
    }

    public static byte[] Unpad(int blockSize, byte[] data)
    {
        if (data.Length == 0 || data.Length % blockSize != 0)
            throw new CryptographicException("Invalid padded data");
        byte pad = data[^1];
        if (pad == 0 || pad > blockSize) throw new CryptographicException("Invalid padding");
        for (int i = data.Length - pad; i < data.Length; i++)
            if (data[i] != pad) throw new CryptographicException("Invalid padding");
        byte[] result = new byte[data.Length - pad];
        Buffer.BlockCopy(data, 0, result, 0, result.Length);
        return result;
    }
}
