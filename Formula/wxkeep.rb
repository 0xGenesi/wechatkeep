class Wxkeep < Formula
  desc "Dual-architecture anti-revoke toolchain for WeChat 4.x on macOS"
  homepage "https://github.com/0xGenesi/wechatkeep"
  version "0.2.1"
  license "AGPL-3.0"

  on_macos do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.1/wxkeep"
    sha256 "86ea7df6b3083c52b201431b022b2dd94502742b9e6da58a04b79b38d84027e7"
  end

  resource "config" do
    url "https://raw.githubusercontent.com/0xGenesi/wechatkeep/v0.2.1/config.json"
    sha256 "909efdf7c86e69d56c2baed04a220e883dbc3dc156264f3a5af71adf600dbfbc"
  end

  resource "signatures" do
    url "https://raw.githubusercontent.com/0xGenesi/wechatkeep/v0.2.1/signatures.json"
    sha256 "c9357a09c2a056763dfbd85f3ac877ee97e082c1caad1945f42871d8be9a9204"
  end

  resource "runtime" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.1/libwxkeep_runtime.dylib"
    sha256 "407c94f7df652e606da321f603061dd2f77ff772661041d7e15e6b9081e8e8af"
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
