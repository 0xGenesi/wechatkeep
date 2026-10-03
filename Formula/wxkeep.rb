class Wxkeep < Formula
  desc "Dual-architecture anti-revoke toolchain for WeChat 4.x on macOS"
  homepage "https://github.com/0xGenesi/wechatkeep"
  version "0.2.5"
  license "AGPL-3.0"

  on_macos do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.5/wxkeep"
    sha256 "71844763203aa29edc3d3a11c3ee9533250799feb8bcdd8e7a2e96f2124c7f9f"
  end

  resource "config" do
    url "https://raw.githubusercontent.com/0xGenesi/wechatkeep/v0.2.5/config.json"
    sha256 "84f3f3870b04ba5f0973a1a62503a6d9bed4e2e5d58d07db71de0856d3ff38c3"
  end

  resource "signatures" do
    url "https://raw.githubusercontent.com/0xGenesi/wechatkeep/v0.2.5/signatures.json"
    sha256 "0dd7bf66d772c2f6fd4b1b8fc1ccae6d3e71331e7296a5eb90edf12cc6c3acc1"
  end

  resource "runtime" do
    url "https://github.com/0xGenesi/wechatkeep/releases/download/v0.2.5/libwxkeep_runtime.dylib"
    sha256 "c33ad8b84221f11ee8bbfd8fb83c137c3dc375bc4edef8c9d9e75dd669243dbb"
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
