#!/bin/bash
# push-to-github.sh — 建仓后一键推送（SSH 或 HTTPS 均可）
# 用法:
#   ./tools/push-to-github.sh <你的GitHub用户名> [仓库名，默认 wechatkeep]
# 前置（三选一）:
#   a) 本机 SSH 公钥已添加到 GitHub 账号（Settings → SSH keys）
#   b) gh 已安装并 `gh auth login`
#   c) 使用 HTTPS + personal access token（脚本会提示）
set -euo pipefail
cd "$(dirname "$0")/.."

USER="${1:?用法: $0 <GitHub用户名> [仓库名]}"
REPO="${2:-wechatkeep}"
SSH_REMOTE="git@github.com:${USER}/${REPO}.git"
HTTPS_REMOTE="https://github.com/${USER}/${REPO}.git"

echo "==> 检测推送通道"
if ssh -T -o BatchMode=yes -o ConnectTimeout=8 git@github.com 2>&1 | grep -q "successfully authenticated"; then
    REMOTE="$SSH_REMOTE"; echo "SSH 认证可用"
elif command -v gh >/dev/null && gh auth status >/dev/null 2>&1; then
    REMOTE="$HTTPS_REMOTE"; echo "gh 已认证（推送时 gh 作为 credential helper）"
    git config credential.helper "!gh auth git-credential"
else
    REMOTE="$HTTPS_REMOTE"
    echo "未检测到 SSH/gh —— 将使用 HTTPS，用户名=${USER}，密码请填 personal access token（repo 权限）"
fi

if git remote get-url origin >/dev/null 2>&1; then
    git remote set-url origin "$REMOTE"
else
    git remote add origin "$REMOTE"
fi

echo "==> 推送 master 与 tags 到 $REMOTE"
git push -u origin master --tags

echo "==> 完成。到 https://github.com/${USER}/${REPO}/actions 确认："
echo "    1) CI（push 触发）两个 macOS 矩阵全绿"
echo "    2) watch-wechat 可手动 Dispatch 一次验证（无新版本时应优雅空跑）"
