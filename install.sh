#!/bin/bash
set -e

# Этап 1: Определение URL репозитория
# Замените USERNAME и REPO_NAME на ваши данные после публикации на GitHub
USERNAME="Vinton777"
REPO_NAME="network-cidr-test-ip"
BRANCH="master"
BASE_URL="https://raw.githubusercontent.com/$USERNAME/$REPO_NAME/$BRANCH"

if [ -d "/data/data/com.termux" ]; then
    export PREFIX="/data/data/com.termux/files/usr"
    INSTALL_DIR="$PREFIX/opt/netblock_analyzer"
    BIN_CMD="$PREFIX/bin/netblock_analyzer"
    IS_TERMUX=1
else
    INSTALL_DIR="/opt/netblock_analyzer"
    BIN_CMD="/usr/local/bin/netblock_analyzer"
    IS_TERMUX=0

    if [ "$EUID" -ne 0 ] && [ "$(id -u)" -ne 0 ]; then
        echo "Пожалуйста, запустите установку от имени root (через sudo)"
        exit 1
    fi
fi

echo "Установка NetBlock Analyzer..."

# Проверка наличия curl
if ! command -v curl >/dev/null 2>&1; then
    echo "curl не найден. Попытка установки..."
    if [ "$IS_TERMUX" = "1" ]; then
        pkg update -y && pkg install -y curl
    elif command -v apt >/dev/null 2>&1; then
        apt update && apt install -y curl
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl
    else
        echo "Пожалуйста, установите curl вручную."
        exit 1
    fi
fi

echo "Создание директории $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"

echo "Загрузка файлов скрипта..."
curl -fsSL "$BASE_URL/netblock_analyzer.sh" -o "$INSTALL_DIR/netblock_analyzer.sh"
curl -fsSL "$BASE_URL/netblock_analyzer.py" -o "$INSTALL_DIR/netblock_analyzer.py"
curl -fsSL "$BASE_URL/cidr.txt" -o "$INSTALL_DIR/cidr.txt"
curl -fsSL "$BASE_URL/ip.txt" -o "$INSTALL_DIR/ip.txt"
curl -fsSL "$BASE_URL/cidr_ufo.txt" -o "$INSTALL_DIR/cidr_ufo.txt"
curl -fsSL "$BASE_URL/cidr_selectel.txt" -o "$INSTALL_DIR/cidr_selectel.txt"
curl -fsSL "$BASE_URL/cidr_selectel_1.txt" -o "$INSTALL_DIR/cidr_selectel_1.txt"
curl -fsSL "$BASE_URL/cidr_selectel_2.txt" -o "$INSTALL_DIR/cidr_selectel_2.txt"
curl -fsSL "$BASE_URL/cidr_cloudru.txt" -o "$INSTALL_DIR/cidr_cloudru.txt"
curl -fsSL "$BASE_URL/cidr_yandex.txt" -o "$INSTALL_DIR/cidr_yandex.txt"
curl -fsSL "$BASE_URL/cidr_vk.txt" -o "$INSTALL_DIR/cidr_vk.txt"
curl -fsSL "$BASE_URL/cidr_regru.txt" -o "$INSTALL_DIR/cidr_regru.txt"

chmod +x "$INSTALL_DIR/netblock_analyzer.sh"

echo "Создание символической ссылки..."
ln -sf "$INSTALL_DIR/netblock_analyzer.sh" "$BIN_CMD"

echo ""
echo "Установка успешно завершена!"
echo "Теперь вы можете запустить NetBlock Analyzer из любой директории командой: netblock_analyzer"

echo "Открываем папку с установленными файлами ($INSTALL_DIR)..."
cd "$INSTALL_DIR" || exit
exec "${SHELL:-bash}" < /dev/tty
