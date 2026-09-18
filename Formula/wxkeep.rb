class Wxkeep < Formula
  desc "Dual-architecture anti-revoke toolchain for WeChat 4.x on macOS"
  homepage "https://github.com/0xGenesi/wechatkeep"
  version "0.2.0"
  license "AGPL-3.0"

  on_macos do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.0/wxkeep"
    sha256 "ebf21c1499cc93be92ee30cb3cce1060232ae2aca650b37338aac3dda48376f5"
  end

  resource "config" do
    url "https://raw.githubusercontent.com/0xGenesi/wechatkeep/v0.2.0/config.json"
    sha256 "dc3f2b82402221ec196a4e4a041a503c8ce12d11ded50245635ef402fa6f0428"
  end

  resource "signatures" do
    url "https://raw.githubusercontent.com/0xGenesi/wechatkeep/v0.2.0/signatures.json"
    sha256 "c9357a09c2a056763dfbd85f3ac877ee97e082c1caad1945f42871d8be9a9204"
  end

  resource "runtime" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.0/libwxkeep_runtime.dylib"
    sha256 "f132b130d2287f8b2d9df192101eb967d44374c0568925a10471dfdeb1eda6d3"
  end

  def install
    bin.install "wxkeep"
    system "xattr", "-c", bin/"wxkeep"
    # config/signatures 放 bin 旁（CLI 的本地优先搜索从可执行文件目录向上走）
    resource("config").stage { bin.install "config.json" }
    resource("signatures").stage { bin.install "signatures.json" }
    # runtime dylib（可选功能）：装到 lib/，`wxkeep runtime install` 会
    # 经符号链接解析 Cellar 布局自动找到它
    resource("runtime").stage { lib.install "libwxkeep_runtime.dylib" }
  end

  test do
    system bin/"wxkeep", "--version"
  end
end
