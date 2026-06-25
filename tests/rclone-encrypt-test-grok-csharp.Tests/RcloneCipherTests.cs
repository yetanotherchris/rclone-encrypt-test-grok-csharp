using RcloneEncrypt;

namespace RcloneEncrypt.Tests;

public class RcloneCipherTests
{
    [Fact]
    public void Filename_Roundtrip_Base32_WithSalt()
    {
        using var c = new RcloneCipher("Testpassword1", "somesalt");
        string p = "dir/sub/file.txt";
        c.DecryptFileName(c.EncryptFileName(p)).Should().Be(p);
    }

    [Fact]
    public void Filename_Roundtrip_Base64_NoSalt()
    {
        using var c = new RcloneCipher("Testpassword1", null, RcloneCipher.NameMode.Standard, RcloneCipher.NameEncoding.Base64);
        string p = "a b/c d.bin";
        c.DecryptFileName(c.EncryptFileName(p)).Should().Be(p);
    }

    [Fact]
    public void File_Roundtrip_NoSalt()
    {
        using var c = new RcloneCipher("Testpassword1", null);
        byte[] data = "umbrella top kit charge tobacco know distance"u8.ToArray();
        c.DecryptData(c.EncryptData(data)).Should().Equal(data);
    }

    [Fact]
    public void File_Roundtrip_WithSalt_Base64()
    {
        using var c = new RcloneCipher("Testpassword1", "salt", RcloneCipher.NameMode.Standard, RcloneCipher.NameEncoding.Base64);
        byte[] data = Enumerable.Range(0, 2000).Select(i => (byte)(i % 251)).ToArray();
        c.DecryptData(c.EncryptData(data)).Should().Equal(data);
    }

    [Fact]
    public void OffMode_AppendsBin()
    {
        using var c = new RcloneCipher("pw", null, RcloneCipher.NameMode.Off);
        c.EncryptFileName("x/y.txt").Should().Be("x/y.txt.bin");
        c.DecryptFileName("x/y.txt.bin").Should().Be("x/y.txt");
    }
}
