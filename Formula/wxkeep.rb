class Wxkeep < Formula
  desc "Dual-architecture anti-revoke toolchain for WeChat 4.x on macOS"
  homepage "https://github.com/0xGenesi/wechatkeep"
  version "0.2.3"
  license "AGPL-3.0"

  on_macos do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.3/wxkeep"
    sha256 "a94b5bc3d6624508fcc2ecacda1cf6a9ee9e2dca2b804ed13c002d0ff3323e68"
  end

  resource "config" do
    url "https://raw.githubusercontent.com/0xGenesi/wechatkeep/v0.2.3/config.json"
    sha256 "a71ebd99288cf09952f22c7153e9592629c2db7ecf7a96ef1d70d7fd7c2c7121"
  end

  resource "signatures" do
    url "https://raw.githubusercontent.com/0xGenesi/wechatkeep/v0.2.3/signatures.json"
    sha256 "0dd7bf66d772c2f6fd4b1b8fc1ccae6d3e71331e7296a5eb90edf12cc6c3acc1"
  end

  resource "runtime" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.3/libwxkeep_runtime.dylib"
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
