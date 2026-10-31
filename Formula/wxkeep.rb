class Wxkeep < Formula
  desc "Dual-architecture anti-revoke toolchain for WeChat 3.x/4.x on macOS"
  homepage "https://github.com/0xGenesi/wechatkeep"
  version "0.2.16"
  license "AGPL-3.0"

  # v0.2.16 起源码-only（release 资产停发，MAINTAINING「发版策略」）：
  # 从 git tag 源码构建；数据四件套随仓库分发，安装后走
  # `wxkeep update-data` OTA 升级目录（与随包数据的供应链门同构）。
  url "https://github.com/0xGenesi/wechatkeep.git", tag: "v0.2.16"

  # 与 homebrew-core 纯 SPM 构建惯例对齐（swiftformat 等）：
  # uses_from_macos "swift" 接受 Command Line Tools（CLT 即可构建——与
  # README 一致）；depends_on xcode 会硬性要求完整 Xcode.app，把 CLT-only
  # 用户挡在门外（E2E 实测拒装）。std_swift_args 附带 --disable-sandbox
  # （SPM 沙盒与 brew 构建环境冲突）。
  uses_from_macos "swift" => :build

  def install
    # 不带 --product 过滤：全产品构建才会产出 runtime dylib 与 wxprobe
    # （E2E 实测 --product wxkeep 只建 CLI，lib.install 直接 ENOENT）
    system "swift", "build", *std_swift_args
    bin.install ".build/release/wxkeep"
    # runtime dylib（可选功能）：装到 lib/，`wxkeep runtime install` 会
    # 经符号链接解析 Cellar 布局自动找到它
    lib.install ".build/release/libwxkeep_runtime.dylib"
    # 能力探针（`wxkeep runtime probe`/install 前置门）：辅助可执行件按
    # brew 惯例进 libexec（不进 PATH）；CLI 经符号链接解析 Cellar 布局找到
    libexec.install ".build/release/wxprobe"
    # 数据四件套放 bin 旁（CLI 的本地优先搜索从可执行文件目录向上走；
    # manifest 在场 = brew 布局也过供应链硬门）。git-tag 源码构建时工作
    # 目录即仓库检出，四件套直接取自仓库（后续由 update-data OTA 升级）。
    %w[config.json signatures.json manifest.json manifest.sig].each do |f|
      bin.install f
    end
  end

  test do
    system bin/"wxkeep", "--version"
    # 供应链门在 brew 布局同样生效（manifest 与数据同源）
    system bin/"wxkeep", "manifest", "--dir", bin
  end
end
