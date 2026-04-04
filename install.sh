#!/bin/bash
set -e

# Этап 1: Определение URL репозитория
# Замените USERNAME и REPO_NAME на ваши данные после публикации на GitHub
USERNAME="Vinton777"
REPO_NAME="network-cidr-test-ip"
BRANCH="master"
TAR_URL="https://github.com/$USERNAME/$REPO_NAME/archive/refs/heads/$BRANCH.tar.gz"

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

echo "Установка NetBlock Analyzer и зависимостей..."

# Проверка и установка зависимостей
if [ "$IS_TERMUX" = "1" ]; then
    echo "Обновление пакетов и установка зависимостей в Termux..."
    pkg update -y
    pkg install -y curl tar python inetutils whois
else
    echo "Проверка наличия пакетных менеджеров и установка зависимостей..."
    if command -v apt >/dev/null 2>&1; then
        apt update && apt install -y curl tar python3 iputils-ping whois
    elif command -v yum >/dev/null 2>&1; then
        yum install -y curl tar python3 iputils whois
    else
        echo "Внимание: Не удалось определить пакетный менеджер. Убедитесь, что curl, tar, python3, ping и whois установлены."
    fi
fi

echo "Создание директории $INSTALL_DIR..."
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

echo "Загрузка и распаковка файлов скрипта..."
curl -fsSL "$TAR_URL" | tar -xz -C "$INSTALL_DIR" --strip-components=1

chmod +x "$INSTALL_DIR/netblock_analyzer.sh"

echo "Создание символической ссылки..."
ln -sf "$INSTALL_DIR/netblock_analyzer.sh" "$BIN_CMD"

echo ""
echo "Установка успешно завершена!"
echo "Теперь вы можете запустить NetBlock Analyzer из любой директории командой: netblock_analyzer"

echo "Запуск NetBlock Analyzer..."
cd "$INSTALL_DIR" || exit
netblock_analyzer < /dev/tty

exec "${SHELL:-bash}" < /dev/tty
