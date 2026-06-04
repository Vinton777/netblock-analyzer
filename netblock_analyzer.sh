#!/usr/bin/env bash

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

# Проверка удаленной версии (с обходом кэша)
if command -v curl >/dev/null 2>&1 && curl --version >/dev/null 2>&1; then
    REMOTE_VERSION=$(curl -s "https://raw.githubusercontent.com/Vinton777/network-cidr-test-ip/master/netblock_analyzer.py?nocache=$RANDOM" | grep -m 1 "VERSION =" | cut -d '"' -f 2 || echo "0.0.0")
else
    # Резервный способ через Python, если curl не работает
    REMOTE_VERSION=$(python3 -c "import urllib.request, re, random; req = urllib.request.Request('https://raw.githubusercontent.com/Vinton777/network-cidr-test-ip/master/netblock_analyzer.py?nocache=' + str(random.random()), headers={'User-Agent': 'Mozilla/5.0'}); html = urllib.request.urlopen(req, timeout=5).read().decode('utf-8'); m = re.search(r'VERSION = \"([^\"]+)\"', html); print(m.group(1) if m else '0.0.0')" 2>/dev/null || echo "0.0.0")
fi

if [ "$REMOTE_VERSION" != "0.0.0" ] && [ "$LOCAL_VERSION" != "$REMOTE_VERSION" ]; then
    # Сравниваем версии корректно (1.8.2 > 1.8.1). Обновляем только если REMOTE > LOCAL
    if [ "$(printf '%s\n' "$LOCAL_VERSION" "$REMOTE_VERSION" | sort -V | head -n1)" = "$LOCAL_VERSION" ]; then
        echo -e "\033[33m[!] Найдена новая версия: $REMOTE_VERSION (Текущая: $LOCAL_VERSION)\033[0m"
        echo -e "\033[32m[+] Запуск авто-обновления...\033[0m"
        if command -v curl >/dev/null 2>&1 && curl --version >/dev/null 2>&1; then
            curl -sSL "https://raw.githubusercontent.com/Vinton777/network-cidr-test-ip/master/install.sh?nocache=$RANDOM" | bash
        else
            python3 -c "import urllib.request, random; req = urllib.request.Request('https://raw.githubusercontent.com/Vinton777/network-cidr-test-ip/master/install.sh?nocache=' + str(random.random()), headers={'User-Agent': 'Mozilla/5.0'}); r = urllib.request.urlopen(req); open('temp_install.sh', 'w', encoding='utf-8').write(r.read().decode('utf-8'))"
            bash temp_install.sh
            rm -f temp_install.sh
        fi
        exit 0
    fi
fi

# Запуск Python скрипта в текущей директории пользователя
exec python3 "$PYTHON_SCRIPT" "$PWD"
