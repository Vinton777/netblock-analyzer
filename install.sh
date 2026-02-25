#!/bin/bash
set -e

# Этап 1: Определение URL репозитория
# Замените USERNAME и REPO_NAME на ваши данные после публикации на GitHub
USERNAME="Vinton777"
REPO_NAME="network-cidr-test-ip"
BRANCH="master"
BASE_URL="https://raw.githubusercontent.com/$USERNAME/$REPO_NAME/$BRANCH"

INSTALL_DIR="/opt/network_test"
BIN_CMD="/usr/local/bin/network_test"

if [ "$EUID" -ne 0 ]; then
    echo "Пожалуйста, запустите установку от имени root (через sudo)"
    exit 1
fi

echo "Установка инструмента Network Test..."

# Проверка наличия curl
if ! command -v curl >/dev/null 2>&1; then
    echo "curl не найден. Попытка установки..."
    if command -v apt >/dev/null 2>&1; then
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
curl -sSL "$BASE_URL/network_test.sh" -o "$INSTALL_DIR/network_test.sh"
curl -sSL "$BASE_URL/network_test.py" -o "$INSTALL_DIR/network_test.py"
curl -sSL "$BASE_URL/cidr.txt" -o "$INSTALL_DIR/cidr.txt"

chmod +x "$INSTALL_DIR/network_test.sh"

echo "Создание символической ссылки..."
ln -sf "$INSTALL_DIR/network_test.sh" "$BIN_CMD"

echo ""
echo "Установка успешно завершена!"
echo "Теперь вы можете запустить скрипт из любой директории командой: network_test"
