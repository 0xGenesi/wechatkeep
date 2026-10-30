class Wxkeep < Formula
  desc "Dual-architecture anti-revoke toolchain for WeChat 3.x/4.x on macOS"
  homepage "https://github.com/0xGenesi/wechatkeep"
  version "0.2.15"
  license "AGPL-3.0"

  # 数据资源全部走 release asset（与二进制同域，2026-10 实测 raw.github
  # 对部分网络 connection reset；release 下载 URL 稳定）
  on_macos do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.15/wxkeep"
    sha256 "dffb23905197f839ff6af54fe29c8139de8a015624e6bbcc38989475de9a7ce1"
  end

  resource "config" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.15/config.json"
    sha256 "1fe9700472bfe19b791e2cab38b7fbd536813c5c79741a7e8232e96b75036d3c"
  end

  resource "signatures" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.15/signatures.json"
    sha256 "13eed0ff4fe3ae196bcc4539781fea146fc740b4e4ae5bf48ae32c9c9ed55312"
  end

  resource "runtime" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.15/libwxkeep_runtime.dylib"
    sha256 "378eb0c5ef6b2360870958fb936b0d14d33dca58bc31e7d5a6b979cb8befd7ad"
  end

  resource "manifest" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.15/manifest.json"
    sha256 "0f03516dd51d36ea43120e4491df4587a5efa20da117bd3c667e0c5e1e26434d"
  end

  resource "manifest-sig" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.15/manifest.sig"
    sha256 "92162b9d4723874636ae783303a320cba0c37462577c703b8f79c0f7a5f6ca8e"
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
