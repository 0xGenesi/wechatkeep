class Wxkeep < Formula
  desc "Dual-architecture anti-revoke toolchain for WeChat 4.x on macOS"
  homepage "https://github.com/0xGenesi/wechatkeep"
  version "0.1.3"
  license "AGPL-3.0"

  on_macos do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.1.3/wxkeep"
    sha256 "c1136159ab608d12c15062c5a142a12b6894e124ee63da7798ea2a106408f0b2"
  end

  resource "config" do
    url "https://raw.githubusercontent.com/0xGenesi/wechatkeep/v0.1.2/config.json"
    sha256 "7ee404b53f3e15e31397358666f2774de13e8806eb615fed8e036e9da171457a"
  end

  resource "signatures" do
    url "https://raw.githubusercontent.com/0xGenesi/wechatkeep/v0.1.2/signatures.json"
    sha256 "642523f3f0db4a6a7437568e8e48595b30fd89e303be3f1e9683f090ec394f3b"
  end

  def install
    bin.install "wxkeep"
    system "xattr", "-c", bin/"wxkeep"
    # config/signatures 放 bin 旁（CLI 的本地优先搜索从可执行文件目录向上走）
    resource("config").stage { bin.install "config.json" }
    resource("signatures").stage { bin.install "signatures.json" }
  end

  test do
    system bin/"wxkeep", "--version"
  end
end
