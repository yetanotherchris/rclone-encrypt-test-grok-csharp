class RcloneEncryptTestGrokCsharp < Formula
  desc "CLI to encrypt/decrypt files using rclone crypt format"
  homepage "https://github.com/yetanotherchris/rclone-encrypt-test-grok-csharp"
  version "0.1.0"

  on_macos do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt-test-grok-csharp/releases/download/v0.1.0/rclone-encrypt-test-grok-csharp-darwin-arm64.tar.gz"
      sha256 "REPLACE"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt-test-grok-csharp/releases/download/v0.1.0/rclone-encrypt-test-grok-csharp-darwin-amd64.tar.gz"
      sha256 "REPLACE"
    end
  end

  on_linux do
    if Hardware::CPU.arm?
      url "https://github.com/yetanotherchris/rclone-encrypt-test-grok-csharp/releases/download/v0.1.0/rclone-encrypt-test-grok-csharp-linux-arm64.tar.gz"
      sha256 "REPLACE"
    else
      url "https://github.com/yetanotherchris/rclone-encrypt-test-grok-csharp/releases/download/v0.1.0/rclone-encrypt-test-grok-csharp-linux-amd64.tar.gz"
      sha256 "REPLACE"
    end
  end

  def install
    bin.install "rclone-encrypt-test-grok-csharp-darwin-arm64" => "rclone-encrypt-test-grok-csharp" if OS.mac? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-test-grok-csharp-darwin-amd64" => "rclone-encrypt-test-grok-csharp" if OS.mac? && !Hardware::CPU.arm?
    bin.install "rclone-encrypt-test-grok-csharp-linux-arm64" => "rclone-encrypt-test-grok-csharp" if OS.linux? && Hardware::CPU.arm?
    bin.install "rclone-encrypt-test-grok-csharp-linux-amd64" => "rclone-encrypt-test-grok-csharp" if OS.linux? && !Hardware::CPU.arm?
  end

  test do
    assert_match "rclone-encrypt-test-grok-csharp #{version}", shell_output("#{bin}/rclone-encrypt-test-grok-csharp --version")
  end
end
