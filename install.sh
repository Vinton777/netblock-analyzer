#!/usr/bin/env bash
set -e

# Переходим в безопасную директорию, чтобы избежать ошибок getcwd, 
# если скрипт запущен из папки, которая будет удалена
cd /tmp || true

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
DEP_MISSING=0
for cmd in tar whois ping; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        DEP_MISSING=1
        break
    fi
done

# В Termux проверяем python3 отдельно
if [ "$IS_TERMUX" = "1" ] && ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
    DEP_MISSING=1
fi

if [ "$DEP_MISSING" -eq 1 ]; then
    if [ "$IS_TERMUX" = "1" ]; then
        echo "Обновление пакетов и установка зависимостей в Termux..."
        pkg update -y || true
        pkg install -y curl tar python inetutils whois libngtcp2 || true
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
else
    echo "Все зависимости уже установлены, пропуск обновления пакетов."
fi

echo "Создание директории $INSTALL_DIR..."
rm -rf "$INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

echo "Загрузка и распаковка файлов скрипта..."
if command -v curl >/dev/null 2>&1 && curl --version >/dev/null 2>&1; then
    curl -fsSL "$TAR_URL" | tar -xz -C "$INSTALL_DIR" --strip-components=1
else
    echo "Предупреждение: curl поврежден или не работает. Скачиваем через Python..."
    PYTHON_CMD="python3"
    if ! command -v python3 >/dev/null 2>&1; then
        if command -v python >/dev/null 2>&1; then
            PYTHON_CMD="python"
        else
            echo "Ошибка: Python не найден. Установка невозможна."
            exit 1
        fi
    fi
    TMP_ARCHIVE="${TMPDIR:-/tmp}/archive.tar.gz"
    $PYTHON_CMD -c "import urllib.request; req = urllib.request.Request('$TAR_URL', headers={'User-Agent': 'Mozilla/5.0'}); open('$TMP_ARCHIVE', 'wb').write(urllib.request.urlopen(req).read())"
    tar -xzf "$TMP_ARCHIVE" -C "$INSTALL_DIR" --strip-components=1
    rm -f "$TMP_ARCHIVE"
fi

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
