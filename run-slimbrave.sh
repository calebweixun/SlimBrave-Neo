#!/usr/bin/env bash
set -e

# 偵測作業系統 (OS)
OS="$(uname -s)"
case "${OS}" in
    Linux*)     SCRIPT="slimbrave-linux.py";;
    Darwin*)    SCRIPT="slimbrave-mac.py";;
    *)          echo "未知的作業系統: ${OS}"; exit 1;;
esac

# 檢查是否安裝 Python 3
if ! command -v python3 &> /dev/null; then
    echo "錯誤: 找不到 python3，請先安裝 Python 3。"
    exit 1
fi

# ==========================================
# 虛擬環境 (Virtual Environment) 處理
# 雖然目前專案僅依賴 Python 內建函式庫 (curses 等)，
# 但依據您的要求，若需要環境隔離，我們預設在此建立虛擬環境。
# ==========================================
VENV_DIR=".venv"
if [ ! -d "$VENV_DIR" ]; then
    echo "正在建立 Python 虛擬環境 ($VENV_DIR)..."
    python3 -m venv "$VENV_DIR"
fi

# 啟用虛擬環境
source "$VENV_DIR/bin/activate"

# 若未來有 requirements.txt 可以這樣安裝：
# if [ -f "requirements.txt" ]; then
#     pip install -r requirements.txt -q
# fi

# 檢查目標 Python 腳本是否存在
if [ ! -f "$SCRIPT" ]; then
    echo "錯誤: 找不到對應的腳本檔案 $SCRIPT"
    exit 1
fi

# 執行腳本 (由於修改瀏覽器企業政策需要 Root 權限，因此提示使用 sudo)
echo "正在啟動 SlimBrave Neo (${OS} 版)..."
echo "注意：寫入系統政策需要 Root 權限，如果您在 TUI 中遇到權限不足，腳本會提示。"

# 針對 TUI 的執行，我們直接呼叫 python 執行，並將額外參數 "$@" 傳入
# 由於 sudo 環境下可能會找不到使用者的 venv，我們使用 sudo 執行 venv 內的 python
sudo "$VENV_DIR/bin/python" "$SCRIPT" "$@"

# 停用虛擬環境
deactivate
