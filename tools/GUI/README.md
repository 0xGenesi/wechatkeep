# WeChatKeep GUI（菜单栏面板）

零依赖 AppKit 菜单栏应用：展示 `wxkeep doctor --json` 的实时状态，
并把 doctor 给出的 `next_command` 一键复制 / 一键在终端执行。

刻意不做的事：**GUI 不做提权**。patch/restore 需要 root，提权属于特权助手
课题；在此之前 GUI 的职责边界是「只读状态 + 命令代备」，无攻击面。

## 构建

```bash
cd Tools/GUI
swift build -c release
```

## 打包成 .app（可选）

```bash
make -C Tools/GUI app     # 产物 Tools/GUI/WeChatKeep.app（含 universal 说明见 Makefile）
open Tools/GUI/WeChatKeep.app
```

## CLI 定位顺序

1. 环境变量 `WXKEEP_GUI_CLI`
2. 可执行文件同目录下的 `wxkeep`
3. `/usr/local/bin/wxkeep`（brew 安装）
