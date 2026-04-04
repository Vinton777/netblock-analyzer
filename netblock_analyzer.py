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

def check_ping(ip, timeout):
    # Пинг 2 пакета
    cmd = ['ping', '-c', '2', '-W', str(timeout), str(ip)]
    try:
        res = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return res.returncode == 0
    except Exception:
        return False

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
        # strict=False позволяет принимать сети вида 192.168.1.5/24 и приводить их к базовому адресу
        network = ipaddress.IPv4Network(cidr_str, strict=False)
    except Exception:
        return None  # Некорректный или не-IPv4 CIDR
    
    total_ips = network.num_addresses
    ips = []
    
    if total_ips == 1: # /32
        ips.append(network.network_address)
    elif total_ips == 2: # /31
        ips.append(network.network_address)
        if num_ips > 1:
            ips.append(network.network_address + 1)
    else:
        first_ip = network.network_address + 1
        last_ip = network.broadcast_address - 1
        
        ips.append(first_ip)
        if num_ips > 1:
            if last_ip not in ips:
                ips.append(last_ip)
                
        remaining = num_ips - len(ips)
        if remaining > 0 and total_ips > 4:
            attempts = 0
            added = 0
            # Математическая генерация без создания полного списка в оперативной памяти
            while added < remaining and attempts < remaining * 3:
                rand_ip = network.network_address + random.randint(2, total_ips - 3)
                if rand_ip not in ips:
                    ips.append(rand_ip)
                    added += 1
                attempts += 1
                
    return ips

def evaluate_cidr(cidr_str, ips, timeout, check_asn):
    if ips is None:
        return cidr_str, "Invalid", "--", False, "error"
        
    is_reachable = False
    for ip in ips:
        if check_ping(ip, timeout):
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

VERSION = "1.8.8"

def main():
    work_dir = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    logo_text = f"""
{COLOR_GREEN}███╗   ██╗███████╗████████╗██████╗ ██╗     ██████╗  ██████╗██╗  ██╗{COLOR_RESET}
{COLOR_GREEN}████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██║    ██╔═══██╗██╔════╝██║ ██╔╝{COLOR_RESET}
{COLOR_GREEN}██╔██╗ ██║█████╗     ██║   ██████╔╝██║    ██║   ██║██║     █████╔╝ {COLOR_RESET}
{COLOR_GREEN}██║╚██╗██║██╔══╝     ██║   ██╔══██╗██║    ██║   ██║██║     ██╔═██╗ {COLOR_RESET}
{COLOR_GREEN}██║ ╚████║███████╗   ██║   ██████╔╝███████╗╚██████╔╝╚██████╗██║  ██╗{COLOR_RESET}
{COLOR_GREEN}╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═════╝ ╚══════╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝{COLOR_RESET}
{COLOR_YELLOW}      █████╗ ███╗   ██╗█████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗ {COLOR_RESET}
{COLOR_YELLOW}     ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗{COLOR_RESET}
{COLOR_YELLOW}     ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝{COLOR_YELLOW}
{COLOR_YELLOW}     ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗{COLOR_RESET}
{COLOR_YELLOW}     ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║{COLOR_RESET}
{COLOR_YELLOW}     ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝{COLOR_RESET}
                                                 {COLOR_WHITE}v{VERSION}{COLOR_GRAY} by Vinton{COLOR_RESET}
"""
    options = {
        '1': ("Свой список CIDR", 'cidr.txt', 1),
        '2': ("Свой список IP", 'ip.txt', 2),
        '3': ("UFO", 'cidr_ufo.txt', 1),
        '4': ("Selectel 1", 'cidr_selectel_1.txt', 1),
        '5': ("Selectel 2", 'cidr_selectel_2.txt', 1),
        '6': ("Selectel Old", 'cidr_selectel.txt', 1),
        '7': ("Cloud.ru", 'cidr_cloudru.txt', 1),
        '8': ("Yandex", 'cidr_yandex.txt', 1),
        '9': ("VK", 'cidr_vk.txt', 1),
        '10': ("Reg.ru", 'cidr_regru.txt', 1),
        '11': ("Timeweb", 'timeweb.txt', 1),
        '12': ("CIDR Whitelist", 'cidrwhitelist.txt', 1)
    }
    
    # Динамическая подгрузка из cidr_lists
    cidr_lists_dir = os.path.join(script_dir, "cidr_lists")
    if os.path.isdir(cidr_lists_dir):
        files = sorted(os.listdir(cidr_lists_dir))
        idx = 13
        for f in files:
            if f.endswith('.txt'):
                name_disp = f.replace(".txt", "").replace("__", " ").strip()
                # Сокращение имени: берём первое слово до "-" или "_"
                import re
                parts = re.split(r'[-_]', name_disp)
                short_name = parts[0].strip().capitalize()
                if short_name.upper() == "AS" and len(parts) > 1:
                    short_name = parts[1].strip().capitalize()
                
                options[str(idx)] = (f"{short_name}", os.path.join("cidr_lists", f), 1)
                idx += 1

    config_path = os.path.expanduser("~/.netblock_analyzer.json")
    
    num_ips = 5
    timeout = 2
    max_threads = 20
    check_asn = False
    save_res = True
    selected_option_key = '1'

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
        except Exception:
            pass

    if selected_option_key not in options:
        selected_option_key = '1'

    selected_option = options[selected_option_key]
    filename = selected_option[1]
    mode = selected_option[2]

    while True:
        clear_screen()
        print(logo_text)
        print(f"\n{COLOR_GREEN}Главное меню:{COLOR_RESET}")
        print(f"{COLOR_YELLOW}1. Выбрать список для проверки (сейчас выбран: {selected_option[0]}){COLOR_RESET}")
        print(f"{COLOR_YELLOW}2. Настройки проверки сети{COLOR_RESET}")
        print(f"{COLOR_YELLOW}3. Редактировать свои списки (cidr.txt / ip.txt){COLOR_RESET}")
        print(f"{COLOR_YELLOW}4. Начать тест{COLOR_RESET}")
        print(f"{COLOR_YELLOW}0. Выход{COLOR_RESET}")
        
        main_choice = safe_input(f" {COLOR_GREEN}[?]{COLOR_RESET} {COLOR_YELLOW}Ваш выбор{COLOR_RESET} [4]: ")
        if main_choice is None:
            continue
        main_choice = main_choice.strip()
        if not main_choice:
            main_choice = '4'
            
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
            import json
            try:
                with open(config_path, "w", encoding="utf-8") as f:
                    json.dump({
                        "num_ips": num_ips,
                        "timeout": timeout,
                        "max_threads": max_threads,
                        "check_asn": check_asn,
                        "save_res": save_res,
                        "selected_option_key": selected_option_key
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
    results_file = os.path.join(work_dir, f"results_{base_name}.csv")


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

    print(f"\n{COLOR_GREEN}{'CIDR/IP':<18} | {'ASN':<12} | {'Provider':<25} | {'PING'}{COLOR_RESET}")

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
            future_to_cidr = {}
            for cidr_str in tasks:
                ips = get_ips_to_test(cidr_str, num_ips)
                future = executor.submit(evaluate_cidr, cidr_str, ips, timeout, check_asn)
                future_to_cidr[future] = cidr_str
                
            for future in concurrent.futures.as_completed(future_to_cidr):
                cidr_str = future_to_cidr[future]
                try:
                    res_cidr, asn, provider, is_reachable, status = future.result()
                    
                    if status == "error":
                        print(f"{res_cidr:<18} | {'Invalid':<12} | {'--':<25} | \033[91merror\033[0m")
                        continue
                        
                    if len(provider) > 22:
                        provider_disp = provider[:19] + "..."
                    else:
                        provider_disp = provider
                        
                    ping_status = "yes" if is_reachable else "no"
                    ping_color = "\033[92myes\033[0m" if is_reachable else "\033[91mno\033[0m"
                    
                    print(f"{res_cidr:<18} | {asn:<12} | {provider_disp:<25} | {ping_color}")
                    
                    if is_reachable:
                        results.append([res_cidr, asn, provider, ping_status])
                        
                except Exception as exc:
                    print(f"{cidr_str:<18} | {'Error':<12} | {'--':<25} | \033[91merror\033[0m")
                    
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
