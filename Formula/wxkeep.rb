class Wxkeep < Formula
  desc "Dual-architecture anti-revoke toolchain for WeChat 4.x on macOS"
  homepage "https://github.com/0xGenesi/wechatkeep"
  version "0.2.11"
  license "AGPL-3.0"

  # 数据资源全部走 release asset（与二进制同域，2026-10 实测 raw.github
  # 对部分网络 connection reset；release 下载 URL 稳定）
  on_macos do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.11/wxkeep"
    sha256 "d2bba86048817f2d1a3b9fc5a7c16a180ca81103bfead8dac34898f17f1a5c34"
  end

  resource "config" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.11/config.json"
    sha256 "378fe9b3c46c111638e9eca628aa5be4c0ec4f193aea4013be05cd1226f9fc0e"
  end

  resource "signatures" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.11/signatures.json"
    sha256 "13eed0ff4fe3ae196bcc4539781fea146fc740b4e4ae5bf48ae32c9c9ed55312"
  end

  resource "runtime" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.11/libwxkeep_runtime.dylib"
    sha256 "2f6df73f86f76c8cf02e25b667b4e237c774fc6067f3ea75819b0bc2b59519f5"
  end

  resource "manifest" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.11/manifest.json"
    sha256 "6138718bb981d11a33d23aab330cbb95d29fca0b8d599bed869189535bdb800a"
  end

  resource "manifest-sig" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.11/manifest.sig"
    sha256 "d9b5c8ccd41faaf47be8eb2ae855d89abe1cce8acf363754c7fbe1eb3d0a8768"
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
