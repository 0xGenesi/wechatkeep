class Wxkeep < Formula
  desc "Dual-architecture anti-revoke toolchain for WeChat 4.x on macOS"
  homepage "https://github.com/0xGenesi/wechatkeep"
  version "0.2.5"
  revision 1
  license "AGPL-3.0"

  # 数据资源全部走 release asset（与二进制同域，2026-10 实测 raw.github
  # 对部分网络 connection reset；release 下载 URL 稳定）
  on_macos do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.5/wxkeep"
    sha256 "71844763203aa29edc3d3a11c3ee9533250799feb8bcdd8e7a2e96f2124c7f9f"
  end

  resource "config" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.5/config.json"
    sha256 "84f3f3870b04ba5f0973a1a62503a6d9bed4e2e5d58d07db71de0856d3ff38c3"
  end

  resource "signatures" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.5/signatures.json"
    sha256 "0dd7bf66d772c2f6fd4b1b8fc1ccae6d3e71331e7296a5eb90edf12cc6c3acc1"
  end

  resource "runtime" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.5/libwxkeep_runtime.dylib"
    sha256 "c33ad8b84221f11ee8bbfd8fb83c137c3dc375bc4edef8c9d9e75dd669243dbb"
  end

  resource "manifest" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.5/manifest.json"
    sha256 "6bc3ef89f457b6b40d566c8f94fc441b9f91de4293794913f2c29c836be0e9cf"
  end

  resource "manifest-sig" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.5/manifest.sig"
    sha256 "c8e405cafbfc874fe7387d5833eb596933d24bccc2cca5b41cd7cd6469cfc787"
  end

  def install
    bin.install "wxkeep"
    system "xattr", "-c", bin/"wxkeep"
    # config/signatures/manifest 放 bin 旁（CLI 的本地优先搜索从可执行文件
    # 目录向上走；manifest 在场 = brew 布局也过供应链硬门）
    resource("config").stage { bin.install "config.json" }
    resource("signatures").stage { bin.install "signatures.json" }
    resource("manifest").stage { bin.install "manifest.json" }
    resource("manifest-sig").stage { bin.install "manifest.sig" }
    # runtime dylib（可选功能）：装到 lib/，`wxkeep runtime install` 会
    # 经符号链接解析 Cellar 布局自动找到它
    resource("runtime").stage { lib.install "libwxkeep_runtime.dylib" }
  end

  test do
    system bin/"wxkeep", "--version"
    # 供应链门在 brew 布局同样生效（manifest 与数据同源）
    system bin/"wxkeep", "manifest", "--dir", bin
  end
end
