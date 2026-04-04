#!/bin/bash

# Функция проверки наличия команды
check_cmd() {
    command -v "$1" >/dev/null 2>&1
}

MISSING=()

check_cmd python3 || MISSING+=("python3")
check_cmd whois || MISSING+=("whois")
check_cmd ping || MISSING+=("ping")
check_cmd tar || MISSING+=("tar")

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "Отсутствуют необходимые зависимости: ${MISSING[*]}"
    echo "Пожалуйста, запустите установочный скрипт для их инсталляции:"
    echo "curl -sSL https://raw.githubusercontent.com/Vinton777/network-cidr-test-ip/master/install.sh | bash"
    exit 1
fi

# Получаем директорию, где находится этот bash-скрипт
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PYTHON_SCRIPT="$SCRIPT_DIR/netblock_analyzer.py"

if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "Ошибка: Не найден файл $PYTHON_SCRIPT"
    exit 1
fi

# Автообновление
# Получаем локальную версию напрямую из Python-файла
LOCAL_VERSION=$(grep -m 1 "VERSION =" "$PYTHON_SCRIPT" | cut -d '"' -f 2 || echo "0.0.0")
# Добавляем ?nocache=$RANDOM для обхода кеша GitHub
REMOTE_VERSION=$(curl -s "https://raw.githubusercontent.com/Vinton777/network-cidr-test-ip/master/netblock_analyzer.py?nocache=$RANDOM" | grep -m 1 "VERSION =" | cut -d '"' -f 2 || echo "0.0.0")

if [ "$REMOTE_VERSION" != "0.0.0" ] && [ "$LOCAL_VERSION" != "$REMOTE_VERSION" ]; then
    # Сравниваем версии корректно (1.8.2 > 1.8.1). Обновляем только если REMOTE > LOCAL
    if [ "$(printf '%s\n' "$LOCAL_VERSION" "$REMOTE_VERSION" | sort -V | head -n1)" = "$LOCAL_VERSION" ]; then
        echo -e "\033[33m[!] Найдена новая версия: $REMOTE_VERSION (Текущая: $LOCAL_VERSION)\033[0m"
        echo -e "\033[32m[+] Запуск авто-обновления...\033[0m"
        curl -sSL "https://raw.githubusercontent.com/Vinton777/network-cidr-test-ip/master/install.sh?nocache=$RANDOM" | bash
        exit 0
    fi
fi

# Запуск Python скрипта в текущей директории пользователя
exec python3 "$PYTHON_SCRIPT" "$PWD"
