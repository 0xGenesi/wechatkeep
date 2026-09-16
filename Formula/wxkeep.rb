class Wxkeep < Formula
  desc "Dual-architecture anti-revoke toolchain for WeChat 4.x on macOS"
  homepage "https://github.com/0xGenesi/wechatkeep"
  version "0.1.0"
  license "AGPL-3.0"

  on_macos do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.1.0/wxkeep"
    sha256 "c8949241a75c221acb508c28988525bdd8051fce9e769a3960bf78656ceacfd2"
  end

  def install
    bin.install "wxkeep"
    system "xattr", "-c", bin/"wxkeep"
  end

  test do
    system bin/"wxkeep", "--version"
  end
end
