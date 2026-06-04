import sys
import os
import subprocess
import ipaddress
import random
import csv
import signal
import concurrent.futures
import threading
import time
import socket
import errno

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def signal_handler(sig, frame):
    print('\n\033[1;31m[!] Прервано пользователем (Ctrl+C). Выход...\033[0m')
    os._exit(0)

signal.signal(signal.SIGINT, signal_handler)

COLOR_RESET = "\033[0m"
COLOR_GREEN = "\033[1;32m"
COLOR_YELLOW = "\033[1;33m"
COLOR_WHITE = "\033[1;37m"
COLOR_RED = "\033[1;31m"
COLOR_GRAY = "\033[0;90m"

def safe_input(prompt_text):
    try:
        return input(prompt_text)
    except EOFError:
        print()
        sys.exit(0)
    except UnicodeDecodeError:
        print(f"\n{COLOR_RED}Ошибка кодировки ввода. Убедитесь, что используете правильную раскладку.{COLOR_RESET}")
        return None
    except KeyboardInterrupt:
        print(f'\n{COLOR_RED}[!] Прервано пользователем (Ctrl+C). Выход...{COLOR_RESET}')
        os._exit(0)

def get_int_input(prompt, default):
    while True:
        val = safe_input(f" {COLOR_GREEN}[?]{COLOR_RESET} {COLOR_YELLOW}{prompt}{COLOR_RESET} [{default}]: ")
        if val is None:
            continue
        val = val.strip()
        if not val:
            return default
        try:
            return int(val)
        except ValueError:
            print(f"{COLOR_RED}Пожалуйста, введите корректное целое число.{COLOR_RESET}")

def get_yes_no_input(prompt, default):
    while True:
        val = safe_input(f" {COLOR_GREEN}[?]{COLOR_RESET} {COLOR_YELLOW}{prompt}{COLOR_RESET} [{default}]: ")
        if val is None:
            continue
        val = val.strip().lower()
        if not val:
            return default.lower() == 'y'
        if val in ('y', 'yes'):
            return True
        if val in ('n', 'no'):
            return False
        print(f"{COLOR_RED}Пожалуйста, введите 'y' или 'n'.{COLOR_RESET}")

def check_host(ip, timeout):
    result = [False]
    result_lock = threading.Lock()
    
    # TCP-подключения к портам 80, 22, 443
    def check_tcp(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            res = s.connect_ex((str(ip), port))
            # 0 — порт открыт. ECONNREFUSED/WSAECONNREFUSED — порт закрыт, но узел жив
            if res == 0 or res in (111, 10061):
                with result_lock:
                    result[0] = True
        except Exception:
            pass
        finally:
            s.close()

    # Системный ICMP-пинг
    def check_icmp():
        if os.name == 'nt':
            cmd = ['ping', '-n', '1', '-w', str(int(timeout * 1000)), str(ip)]
        else:
            cmd = ['ping', '-c', '1', '-W', str(timeout), str(ip)]
        try:
            res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if res.returncode == 0:
                with result_lock:
                    result[0] = True
        except Exception:
            pass

    threads = []
    # Запускаем TCP-проверки портов
    for port in [443, 80, 22]:
        t = threading.Thread(target=check_tcp, args=(port,), daemon=True)
        t.start()
        threads.append(t)
        
    # Запускаем ICMP-пинг
    t_icmp = threading.Thread(target=check_icmp, daemon=True)
    t_icmp.start()
    threads.append(t_icmp)
    
    # Ждём завершения или первого успешного ответа
    start_t = time.time()
    while time.time() - start_t < timeout + 0.2:
        with result_lock:
            if result[0]:
                return True
        if not any(t.is_alive() for t in threads):
            break
        time.sleep(0.02)
        
    with result_lock:
        return result[0]

def check_ip_task(ip, cidr, timeout, cidr_status, results_lock):
    with results_lock:
        if cidr_status.get(cidr) == "yes":
            return ip, cidr, False, True  # Пропускаем, так как CIDR уже доступен
            
    is_reachable = check_host(ip, timeout)
    return ip, cidr, is_reachable, False

asn_cache = {}
whois_lock = threading.Lock()

def get_asn_info(cidr_obj):
    target = str(cidr_obj.network_address)
    
    with whois_lock:
        if target in asn_cache:
            return asn_cache[target]
            
        asn = "Unknown"
        provider = "Unknown"
        
        # Первая попытка: обычный whois
        try:
            cmd = ['whois', target]
            res = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
            output = res.stdout
        except Exception:
            output = ""
            
        # Вторая попытка (особенно для мобильного инета Termux, если обычный молчит)
        if not output or "not found" in output.lower() or "no entries found" in output.lower():
            try:
                cmd_fallback = ['whois', '-h', 'whois.radb.net', target]
                res2 = subprocess.run(cmd_fallback, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True, timeout=10)
                output += "\n" + res2.stdout
            except Exception:
                pass
        
        # Извлечение данных из whois (расширенный парсинг)
        for line in output.splitlines():
            line = line.strip()
            lower_line = line.lower()
            
            # Поиск ASN
            if lower_line.startswith('origin:') or lower_line.startswith('aut-num:') or lower_line.startswith('asn:'):
                parts = line.split(':', 1)
                if len(parts) > 1 and asn == "Unknown":
                    # Бывает "AS1234", "1234", очищаем
                    val = parts[1].strip().upper()
                    if val.startswith('AS'):
                        asn = val
                    elif val.isdigit():
                        asn = 'AS' + val
            
            # Поиск Provider
            if (lower_line.startswith('as-name:') or lower_line.startswith('org-name:') or 
                lower_line.startswith('netname:') or lower_line.startswith('descr:') or 
                lower_line.startswith('organization:') or lower_line.startswith('owner:')):
                parts = line.split(':', 1)
                if len(parts) > 1 and provider == "Unknown":
                    p = parts[1].strip()
                    if p and p.lower() not in ["none", "na", "-"]:
                        provider = p
        
    asn_cache[target] = (asn, provider)
    return asn, provider

def get_ips_to_test(cidr_str, num_ips):
    try:
        network = ipaddress.IPv4Network(cidr_str, strict=False)
    except Exception:
        return None  # Некорректный или не-IPv4 CIDR
    
    total_ips = network.num_addresses
    
    if total_ips <= 2:
        return [network.network_address + i for i in range(total_ips)]
        
    usable_ips_count = total_ips - 2 if total_ips > 2 else total_ips
    if num_ips >= usable_ips_count:
        return list(network.hosts())
        
    hosts = list(network.hosts())
    if not hosts:
        return []
        
    if len(hosts) <= num_ips:
        return hosts
        
    return random.sample(hosts, num_ips)

def evaluate_cidr(cidr_str, ips, timeout, check_asn):
    # Данная функция оставлена для совместимости, реальная проверка переехала в check_ip_task
    if ips is None:
        return cidr_str, "Invalid", "--", False, "error"
    is_reachable = False
    for ip in ips:
        if check_host(ip, timeout):
            is_reachable = True
            break
    if check_asn:
        asn, provider = get_asn_info(ipaddress.IPv4Network(cidr_str, strict=False))
    else:
        asn, provider = "--", "--"
    return cidr_str, asn, provider, is_reachable, "ok"

def edit_file(filename, work_dir):
    filepath = os.path.join(work_dir, filename)
    if not os.path.exists(filepath):
        try:
            open(filepath, 'a').close()
        except Exception:
            pass
    editor = os.environ.get('EDITOR', 'nano')
    try:
        subprocess.run([editor, filepath])
    except FileNotFoundError:
        if editor == 'nano':
            try:
                subprocess.run(['vi', filepath])
            except Exception as e:
                print(f"{COLOR_RED}Ошибка: редактор не найден ('nano' или 'vi') {e}{COLOR_RESET}")
        else:
            print(f"{COLOR_RED}Ошибка запуска редактора {editor}.{COLOR_RESET}")
    except Exception as e:
        print(f"{COLOR_RED}Ошибка: {e}{COLOR_RESET}")

def get_downloads_folder():
    if os.path.exists("/data/data/com.termux"):
        return "/storage/emulated/0/Download"
    else:
        return os.path.join(os.path.expanduser("~"), "Downloads")

VERSION = "2.0.9"

def check_for_updates(auto_update):
    if not auto_update:
        return
        
    import urllib.request
    import urllib.error
    url = "https://raw.githubusercontent.com/Vinton777/network-cidr-test-ip/master/netblock_analyzer.py"
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=5) as response:
            content = response.read().decode('utf-8')
        remote_version = None
        for line in content.splitlines():
            if line.startswith("VERSION = "):
                remote_version = line.split('"')[1]
                break
        if remote_version and remote_version != VERSION:
            v_remote = [int(x) for x in remote_version.split('.')]
            v_local = [int(x) for x in VERSION.split('.')]
            if v_remote > v_local:
                print(f"\n{COLOR_GREEN}[+] Автообновление до версии {remote_version}...{COLOR_RESET}")
                try:
                    import random
                    import tempfile
                    inst_url = f"https://raw.githubusercontent.com/Vinton777/network-cidr-test-ip/master/install.sh?nocache={random.random()}"
                    req_inst = urllib.request.Request(inst_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req_inst, timeout=10) as resp_inst:
                        install_script = resp_inst.read().decode('utf-8')
                    temp_dir = tempfile.gettempdir()
                    temp_path = os.path.join(temp_dir, "temp_install.sh")
                    with open(temp_path, "w", encoding="utf-8") as f_inst:
                        f_inst.write(install_script)
                    os.system(f"bash {temp_path}")
                    if os.path.exists(temp_path):
                        os.remove(temp_path)
                except Exception:
                    os.system("curl -sSL https://raw.githubusercontent.com/Vinton777/network-cidr-test-ip/master/install.sh | bash")
                print(f"{COLOR_GREEN}Готово. Пожалуйста, перезапустите скрипт.{COLOR_RESET}")
                import sys
                sys.exit(0)
    except Exception:
        pass  # Игнорируем ошибки сети при проверке обновлений

def main():
    if sys.platform == "win32":
        try:
            import io
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        except Exception:
            pass
    work_dir = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    logo_text = f"""
{COLOR_GREEN}███╗   ██╗███████╗████████╗██████╗ ██╗     ██████╗  ██████╗██╗  ██╗{COLOR_RESET}
{COLOR_GREEN}████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║    ██╔═══██╗██╔════╝██║ ██╔╝{COLOR_RESET}
{COLOR_GREEN}██╔██╗ ██║█████╗     ██║   ██████╔╝██║    ██║   ██║██║     █████╔╝ {COLOR_RESET}
{COLOR_GREEN}██║╚██╗██║██╔══╝     ██║   ██╔══██╗██║    ██║   ██║██║     ██╔═██╗ {COLOR_RESET}
{COLOR_GREEN}██║ ╚████║███████╗   ██║   ██████╔╝███████╗██████╔╝╚██████╗██║  ██╗{COLOR_RESET}
{COLOR_GREEN}╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝{COLOR_RESET}
{COLOR_YELLOW}      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ {COLOR_RESET}
{COLOR_YELLOW}     ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗{COLOR_RESET}
{COLOR_YELLOW}     ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝{COLOR_YELLOW}
{COLOR_YELLOW}     ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗{COLOR_RESET}
{COLOR_YELLOW}     ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║{COLOR_RESET}
{COLOR_YELLOW}     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝{COLOR_RESET}
                                                 {COLOR_WHITE}v{VERSION}{COLOR_GRAY} by Vinton{COLOR_RESET}
"""
    options = {
        '1': ("Свой список CIDR", 'cidr.txt', 1),
        '2': ("Свой список IP", 'ip.txt', 2)
    }
    
    # Динамическая подгрузка из cidr_lists
    cidr_lists_dir = os.path.join(script_dir, "cidr_lists")
    if os.path.isdir(cidr_lists_dir):
        files = sorted(os.listdir(cidr_lists_dir))
        idx = 3
        for f in files:
            if f.endswith('.txt') and f not in ['cidr.txt', 'ip.txt']:
                name_disp = f.replace(".txt", "").replace("cidr_", "").replace("cidr", "").replace("_", " ").replace("(new)", " New").replace("(", "").replace(")", "").strip().title()
                
                # Фикс частых аббревиатур
                name_disp = name_disp.replace("Ufo", "UFO").replace("Vk", "VK")
                if not name_disp:
                    name_disp = f
                
                options[str(idx)] = (name_disp, os.path.join("cidr_lists", f), 1)
                idx += 1

    config_path = os.path.expanduser("~/.netblock_analyzer.json")
    
    num_ips = 5
    timeout = 2
    max_threads = 20
    check_asn = False
    save_res = True
    selected_option_key = '1'
    silent_mode = False
    auto_update = False

    if os.path.exists(config_path):
        import json
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                num_ips = cfg.get("num_ips", num_ips)
                timeout = cfg.get("timeout", timeout)
                max_threads = cfg.get("max_threads", max_threads)
                check_asn = cfg.get("check_asn", check_asn)
                save_res = cfg.get("save_res", save_res)
                selected_option_key = str(cfg.get("selected_option_key", selected_option_key))
                silent_mode = cfg.get("silent_mode", silent_mode)
                auto_update = cfg.get("auto_update", auto_update)
        except Exception:
            pass

    if selected_option_key not in options:
        selected_option_key = '1'

    selected_option = options[selected_option_key]
    filename = selected_option[1]
    mode = selected_option[2]

    # Проверка обновлений при запуске
    check_for_updates(auto_update)

    while True:
        clear_screen()
        print(logo_text)
        print(f"\n{COLOR_GREEN}Главное меню:{COLOR_RESET}")
        print(f"{COLOR_YELLOW}1. Выбрать список для проверки (сейчас выбран: {selected_option[0]}){COLOR_RESET}")
        print(f"{COLOR_YELLOW}2. Настройки проверки сети{COLOR_RESET}")
        print(f"{COLOR_YELLOW}3. Редактировать свои списки (cidr.txt / ip.txt){COLOR_RESET}")
        
        auto_update_text = "Вкл" if auto_update else "Выкл"
        print(f"{COLOR_YELLOW}4. Автообновление (сейчас: {auto_update_text}){COLOR_RESET}")
        
        print(f"{COLOR_YELLOW}5. Начать тест{COLOR_RESET}")
        print(f"{COLOR_YELLOW}0. Выход{COLOR_RESET}")
        
        main_choice = safe_input(f" {COLOR_GREEN}[?]{COLOR_RESET} {COLOR_YELLOW}Ваш выбор{COLOR_RESET} [5]: ")
        if main_choice is None:
            continue
        main_choice = main_choice.strip()
        if not main_choice:
            main_choice = '5'
            
        if main_choice == '0':
            sys.exit(0)
        elif main_choice == '1':
            while True:
                print(f"\n{COLOR_GREEN}Выберите список для проверки:{COLOR_RESET}\n")
                for k, v in options.items():
                    print(f"{COLOR_YELLOW}{k}. {v[0]} ({v[1]}){COLOR_RESET}")
                print(f"{COLOR_YELLOW}0. Назад{COLOR_RESET}\n")
                mode_val = safe_input(f" {COLOR_GREEN}[?]{COLOR_RESET} {COLOR_YELLOW}Ваш выбор{COLOR_RESET} [0]: ")
                if mode_val is None:
                    continue
                mode_val = mode_val.strip()
                if not mode_val or mode_val == '0':
                    break
                if mode_val in options:
                    selected_option_key = mode_val
                    selected_option = options[mode_val]
                    filename = selected_option[1]
                    mode = selected_option[2]
                    if mode != 1:
                        num_ips = 1
                    break
                print(f"{COLOR_RED}Пожалуйста, введите корректное число.{COLOR_RESET}\n")
        elif main_choice == '2':
            print(f"\n{COLOR_RED}Внимание: изменение настроек пинга на ваш страх и риск. Не ручаюсь за них.{COLOR_RESET}")
            sure = get_yes_no_input("Вы уверены, что хотите изменить параметры? (y/n)", "n")
            if sure:
                print(f"\n{COLOR_GREEN}Настройки проверки сети{COLOR_RESET}\n")
                if mode == 1:
                    num_ips = get_int_input("Сколько IP проверять для каждого CIDR?", num_ips)
                timeout = get_int_input("Timeout для ping в секундах?", timeout)
                max_threads = get_int_input("Сколько потоков использовать?", max_threads)
                
                check_asn_def = "y" if check_asn else "n"
                check_asn = get_yes_no_input("Отображать ASN и провайдера? (y/n) (может не работать при блокировках)", check_asn_def)
                
                save_res_def = "y" if save_res else "n"
                save_res = get_yes_no_input(f"Сохранять результаты? (y/n)", save_res_def)
        elif main_choice == '3':
            while True:
                clear_screen()
                print(logo_text)
                print(f"\n{COLOR_GREEN}Редактирование списков:{COLOR_RESET}")
                print(f"{COLOR_YELLOW}1. cidr.txt (Свой список CIDR){COLOR_RESET}")
                print(f"{COLOR_YELLOW}2. ip.txt (Свой список IP){COLOR_RESET}")
                print(f"{COLOR_YELLOW}0. Назад{COLOR_RESET}")
                
                edit_choice = safe_input(f" {COLOR_GREEN}[?]{COLOR_RESET} {COLOR_YELLOW}Ваш выбор{COLOR_RESET} [0]: ")
                if edit_choice is None: continue
                edit_choice = edit_choice.strip()
                
                if edit_choice == '1':
                    edit_file('cidr.txt', work_dir)
                elif edit_choice == '2':
                    edit_file('ip.txt', work_dir)
                elif edit_choice == '0' or not edit_choice:
                    break
                else:
                    print(f"{COLOR_RED}Неверный выбор.{COLOR_RESET}")
                    time.sleep(1)
        elif main_choice == '4':
            auto_update = not auto_update
            # Сразу сохраним
            import json
            try:
                with open(config_path, "w", encoding="utf-8") as f:
                    json.dump({
                        "num_ips": num_ips,
                        "timeout": timeout,
                        "max_threads": max_threads,
                        "check_asn": check_asn,
                        "save_res": save_res,
                        "selected_option_key": selected_option_key,
                        "silent_mode": silent_mode,
                        "auto_update": auto_update
                    }, f)
            except Exception:
                pass
            print(f"{COLOR_GREEN}Раздел автообновления: {'Включено' if auto_update else 'Выключено'}.{COLOR_RESET}")
            time.sleep(1)
        elif main_choice == '5':
            clear_screen()
            print(logo_text)
            print(f"\n{COLOR_GREEN}Перед началом выберите режим отображения:{COLOR_RESET}")
            
            print(f"{COLOR_YELLOW}1. Обычный (показывать каждый пинг){COLOR_RESET}")
            print(f"{COLOR_YELLOW}2. Тихий (скрыть процесс, показать только итог и таймер){COLOR_RESET}")
            
            mode_choice = safe_input(f" {COLOR_GREEN}[?]{COLOR_RESET} {COLOR_YELLOW}Ваш выбор{COLOR_RESET} [1]: ")
            if mode_choice is None: continue
            mode_choice = mode_choice.strip()
            if not mode_choice:
                mode_choice = '1'
                
            silent_mode = (mode_choice == '2')
            
            import json
            try:
                with open(config_path, "w", encoding="utf-8") as f:
                    json.dump({
                        "num_ips": num_ips,
                        "timeout": timeout,
                        "max_threads": max_threads,
                        "check_asn": check_asn,
                        "save_res": save_res,
                        "selected_option_key": selected_option_key,
                        "silent_mode": silent_mode,
                        "auto_update": auto_update
                    }, f)
            except Exception:
                pass
            break
        else:
            print(f"{COLOR_RED}Неверный выбор.{COLOR_RESET}")
            time.sleep(1)
    
    clear_screen()
    print(logo_text)
    
    target_file = os.path.join(work_dir, filename)
    if not os.path.exists(target_file):
        fallback_file = os.path.join(script_dir, filename)
        if os.path.exists(fallback_file):
            target_file = fallback_file
        else:
            print(f"{COLOR_RED}Ошибка: Файл {filename} не найден ни в текущей папке ({work_dir}), ни в системной ({script_dir}).{COLOR_RESET}")
            sys.exit(1)
            
    base_name = os.path.basename(filename).replace(".txt", "")
    downloads_dir = get_downloads_folder()
    if not os.path.exists(downloads_dir):
        try:
            os.makedirs(downloads_dir, exist_ok=True)
        except Exception:
            downloads_dir = work_dir
            
    import datetime
    now_str = datetime.datetime.now().strftime("%d.%m.%y %H-%M")
    results_file = os.path.join(downloads_dir, f"results_{base_name}_{now_str}.csv")

    results = []
    
    tasks = []
    try:
        with open(target_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                item_str = line.split()[0]
                tasks.append(item_str)
    except Exception as e:
        print(f"Ошибка чтения {filename}: {e}")
        sys.exit(1)

    if not silent_mode:
        print(f"\n{COLOR_GREEN}{'CIDR/IP':<18} | {'ASN':<12} | {'Provider':<25} | {'PING'}{COLOR_RESET}")
    else:
        print(f"\n{COLOR_GREEN}[+] Тихий режим. Тестирование ({len(tasks)} записей)...{COLOR_RESET}")

    start_time = time.time()
    total_tasks = len(tasks)
    
    completed_lock = threading.Lock()
    completed = 0
    test_running = True

    cidr_ips = {}
    cidr_pending = {}
    cidr_status = {}
    cidr_printed = set()
    cidr_asn_info = {}
    results_lock = threading.Lock()

    def print_cidr_result(cidr, status):
        nonlocal completed
        if cidr in cidr_printed:
            return
        cidr_printed.add(cidr)
        
        if status == "error":
            if not silent_mode:
                print(f"{cidr:<18} | {'Invalid':<12} | {'--':<25} | \033[91merror\033[0m")
            with completed_lock:
                completed += 1
            return
            
        if check_asn:
            asn, provider = get_asn_info(ipaddress.IPv4Network(cidr, strict=False))
        else:
            asn, provider = "--", "--"
            
        cidr_asn_info[cidr] = (asn, provider)
        
        if len(provider) > 22:
            provider_disp = provider[:19] + "..."
        else:
            provider_disp = provider
            
        ping_status = "yes" if status == "yes" else "no"
        ping_color = f"\033[92myes\033[0m" if status == "yes" else f"\033[91mno\033[0m"
        
        if not silent_mode:
            print(f"{cidr:<18} | {asn:<12} | {provider_disp:<25} | {ping_color}")
            
        if status == "yes":
            results.append([cidr, asn, provider, ping_status])
            
        with completed_lock:
            completed += 1

    def progress_timer():
        while test_running:
            elapsed = time.time() - start_time
            mins, secs = divmod(int(elapsed), 60)
            with completed_lock:
                current_completed = completed
            sys.stdout.write(f"\r{COLOR_YELLOW}Прогресс: {current_completed}/{total_tasks} [{mins:02d}:{secs:02d}]{COLOR_RESET} ")
            sys.stdout.flush()
            time.sleep(0.2)

    if silent_mode:
        t_thread = threading.Thread(target=progress_timer, daemon=True)
        t_thread.start()

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = []
            
            for cidr_str in tasks:
                ips = get_ips_to_test(cidr_str, num_ips)
                if ips is None or len(ips) == 0:
                    with results_lock:
                        cidr_status[cidr_str] = "error"
                        cidr_pending[cidr_str] = 0
                    print_cidr_result(cidr_str, "error")
                    continue
                    
                with results_lock:
                    cidr_ips[cidr_str] = ips
                    cidr_pending[cidr_str] = len(ips)
                    cidr_status[cidr_str] = "checking"
                    
                for ip in ips:
                    future = executor.submit(check_ip_task, ip, cidr_str, timeout, cidr_status, results_lock)
                    futures.append(future)
                    
            for future in concurrent.futures.as_completed(futures):
                try:
                    ip, cidr, is_reachable, skipped = future.result()
                    
                    with results_lock:
                        if cidr in cidr_printed:
                            cidr_pending[cidr] -= 1
                            continue
                            
                        cidr_pending[cidr] -= 1
                        
                        if is_reachable:
                            cidr_status[cidr] = "yes"
                            print_cidr_result(cidr, "yes")
                        elif cidr_pending[cidr] == 0:
                            cidr_status[cidr] = "no"
                            print_cidr_result(cidr, "no")
                except Exception:
                    pass
                    
        test_running = False
        if silent_mode:
            t_thread.join(timeout=1.0)
            elapsed = time.time() - start_time
            mins, secs = divmod(int(elapsed), 60)
            sys.stdout.write(f"\r{COLOR_YELLOW}Прогресс: {completed}/{total_tasks} [{mins:02d}:{secs:02d}]{COLOR_RESET} ")
            print("\n")
                    
    except KeyboardInterrupt:
        print(f'\n{COLOR_RED}[!] Прервано пользователем (Ctrl+C). Выход...{COLOR_RESET}')
        os._exit(0)
    except Exception as e:
        print(f"\n{COLOR_RED}Ошибка при обработке: {e}{COLOR_RESET}")

    if results:
        print(f"\n{COLOR_GREEN}==== Итоговый список успешных (PING = yes) ===={COLOR_RESET}")
        print(f"{COLOR_GREEN}{'CIDR/IP':<18} | {'ASN':<12} | {'Provider':<25}{COLOR_RESET}")
        for row in results:
            print(f"\033[92m{row[0]:<18}\033[0m | {row[1]:<12} | {row[2]:<25}")
        print(f"{COLOR_GREEN}==============================================={COLOR_RESET}")

    # Сохранение результатов
    if save_res and results:
        try:
            with open(results_file, "w", newline='', encoding="utf-8") as cf:
                writer = csv.writer(cf)
                writer.writerow(["CIDR_OR_IP", "ASN", "PROVIDER", "PING"])
                writer.writerows(results)
            print(f"\n{COLOR_GREEN}[+] Результаты успешно сохранены в {results_file}{COLOR_RESET}")
        except Exception as e:
            print(f"\n{COLOR_RED}[-] Ошибка при сохранении результатов: {e}{COLOR_RESET}")

if __name__ == '__main__':
    main()
