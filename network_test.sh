#!/bin/bash

# Функция проверки наличия команды
check_cmd() {
    command -v "$1" >/dev/null 2>&1
}

MISSING=()

check_cmd python3 || MISSING+=("python3")
check_cmd whois || MISSING+=("whois")
check_cmd ping || MISSING+=("ping")

if [ ${#MISSING[@]} -gt 0 ]; then
    echo "Отсутствуют необходимые зависимости: ${MISSING[*]}"

    if [ -n "$TERMUX_VERSION" ]; then
        echo "Попытка автоматической установки зависимостей в Termux..."
        pkg update -y
        for pkg in "${MISSING[@]}"; do
            if [ "$pkg" = "python3" ]; then
                pkg install -y python
            elif [ "$pkg" = "ping" ]; then
                pkg install -y inetutils
            else
                pkg install -y "$pkg"
            fi
        done
    else
        if [ "$EUID" -ne 0 ]; then
            echo "Ошибка: У вас нет прав root."
            echo "Пожалуйста, запустите скрипт через sudo для установки: ${MISSING[*]}"
            exit 1
        fi

        echo "Попытка автоматической установки зависимостей..."
        if check_cmd apt; then
            apt update && apt install -y "${MISSING[@]}"
        elif check_cmd yum; then
            yum install -y "${MISSING[@]}"
        else
            echo "Неподдерживаемый пакетный менеджер. Пожалуйста, установите вручную: ${MISSING[*]}"
            exit 1
        fi
    fi
fi

# Получаем директорию, где находится этот bash-скрипт
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PYTHON_SCRIPT="$SCRIPT_DIR/network_test.py"

if [ ! -f "$PYTHON_SCRIPT" ]; then
    echo "Ошибка: Не найден файл $PYTHON_SCRIPT"
    exit 1
fi

# Запуск Python скрипта в текущей директории пользователя
exec python3 "$PYTHON_SCRIPT" "$PWD"
