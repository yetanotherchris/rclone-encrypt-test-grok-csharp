using System.Text;

namespace RcloneEncrypt;

internal static class Program
{
    private const string AppName = "rclone-encrypt-test-grok-csharp";

    public static int Main(string[] args)
    {
        try { return Run(args); }
        catch (Exception ex) { Console.Error.WriteLine($"{AppName}: error: {ex.Message}"); return 1; }
    }

    private static int Run(string[] args)
    {
        if (args.Length == 0 || args.Contains("--help") || args.Contains("-h")) { PrintHelp(); return 0; }
        if (args.Contains("--version") || args.Contains("-v")) { Console.WriteLine($"{AppName} 0.1.0"); return 0; }

        bool isEncrypt = args.Contains("encrypt");
        bool isDecrypt = args.Contains("decrypt");
        bool filenameOnly = args.Contains("--filename-only") || args.Contains("--name");

        string? input = GetOption(args, "-i", "--input-file", "--input");
        string? output = GetOption(args, "-o", "--output-file", "--output");
        string? password = GetOption(args, "--password", "-p");
        string? salt = GetOption(args, "--salt", "-s");
        string encodingStr = GetOption(args, "--encoding", "-e") ?? "base32";

        if (input == null) { Console.Error.WriteLine("Error: --input-file is required"); PrintHelp(); return 1; }

        var encoding = ParseEncoding(encodingStr);
        var mode = (args.Contains("--no-filename-encryption") || args.Contains("--filename-encryption=off"))
            ? RcloneCipher.NameMode.Off : RcloneCipher.NameMode.Standard;

        bool usedEnv = false;
        if (string.IsNullOrEmpty(password))
        {
            password = Environment.GetEnvironmentVariable("RCLONE_CRYPT_PASSWORD");
            if (!string.IsNullOrEmpty(password)) usedEnv = true;
            else
            {
                password = ReadSecure("Enter password: ");
                string? s2 = ReadSecure("Enter salt (optional): ");
                if (!string.IsNullOrWhiteSpace(s2)) salt = s2;
            }
        }
        else
        {
            Console.Error.WriteLine("WARNING: Using --password exposes the password. Prefer prompt or RCLONE_CRYPT_PASSWORD env var. Clear shell history after.");
        }
        if (string.IsNullOrEmpty(password)) { Console.Error.WriteLine("Error: password required"); return 1; }

        using var cipher = new RcloneCipher(password, salt, mode, encoding);

        if (filenameOnly)
        {
            string result = isEncrypt ? cipher.EncryptFileName(input) : cipher.DecryptFileName(input);
            if (output != null) File.WriteAllText(output, result, Encoding.UTF8);
            else Console.WriteLine(result);
            return 0;
        }

        if (!File.Exists(input)) { Console.Error.WriteLine($"Error: input not found: {input}"); return 1; }
        byte[] data = File.ReadAllBytes(input);
        byte[] resultBytes = (isEncrypt || (!isDecrypt && args.Contains("encrypt")))
            ? cipher.EncryptData(data)
            : cipher.DecryptData(data);

        string def = isEncrypt ? input + ".bin" : input + ".dec";
        string outPath = output ?? def;
        File.WriteAllBytes(outPath, resultBytes);
        Console.WriteLine($"Wrote {(isEncrypt ? "encrypted" : "decrypted")} file to {outPath}");

        if (!usedEnv) password = new string('\0', password.Length);
        return 0;
    }

    private static void PrintHelp()
    {
        Console.WriteLine($@"{AppName} - rclone crypt compatible CLI

Usage:
  {AppName} encrypt -i <file> [-o <out>] [--password <pw>] [--salt <salt>] [--encoding base32|base64]
  {AppName} decrypt -i <file> [-o <out>] [--password <pw>] [--salt <salt>] [--encoding base32|base64]
  {AppName} (encrypt|decrypt) --filename-only -i <name>

Options:
  -i, --input-file     Input path (required)
  -o, --output-file    Output path (optional)
  --password, -p       Password (prefer prompt or RCLONE_CRYPT_PASSWORD)
  --salt, -s           Optional salt (default = rclone internal)
  --encoding, -e       base32 (default) | base64
  --filename-only      Operate on filename only
  --no-filename-encryption  Disable name encryption (adds .bin)

Security:
  --password leaks to history/ps. Use prompt or env var and clear history.
");
    }

    private static string? GetOption(string[] args, params string[] names)
    {
        for (int i = 0; i < args.Length; i++)
            if (names.Contains(args[i]) && i + 1 < args.Length) return args[i + 1];
        return null;
    }

    private static RcloneCipher.NameEncoding ParseEncoding(string? s)
    {
        s = (s ?? "base32").ToLowerInvariant();
        return (s == "base64" || s == "b64") ? RcloneCipher.NameEncoding.Base64 : RcloneCipher.NameEncoding.Base32;
    }

    private static string ReadSecure(string prompt)
    {
        Console.Error.Write(prompt);
        var sb = new StringBuilder();
        while (true)
        {
            var key = Console.ReadKey(intercept: true);
            if (key.Key == ConsoleKey.Enter) { Console.Error.WriteLine(); break; }
            if (key.Key == ConsoleKey.Backspace) { if (sb.Length > 0) sb.Length--; continue; }
            if (!char.IsControl(key.KeyChar)) sb.Append(key.KeyChar);
        }
        return sb.ToString();
    }
}
