import sys
import os
import subprocess
import ipaddress
import random
import csv
import signal
import concurrent.futures
import threading

def signal_handler(sig, frame):
    print('\n[!] Прервано пользователем (Ctrl+C). Выход...')
    os._exit(0)

signal.signal(signal.SIGINT, signal_handler)

def get_int_input(prompt, default):
    while True:
        val = input(f"{prompt} [{default}]: ").strip()
        if not val:
            return default
        try:
            return int(val)
        except ValueError:
            print("Пожалуйста, введите корректное целое число.")

def get_yes_no_input(prompt, default):
    while True:
        val = input(f"{prompt} [{default}]: ").strip().lower()
        if not val:
            return default.lower() == 'y'
        if val in ('y', 'yes'):
            return True
        if val in ('n', 'no'):
            return False

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

VERSION = "1.2.0"

def main():
    work_dir = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    script_dir = os.path.dirname(os.path.abspath(__file__))
    
    print(f"==========================================")
    print(f"NetBlock Analyzer v{VERSION}")
    print(f"             by Vinton")
    print(f"==========================================")
    
    print("\n--- Режим работы ---")
    options = {
        '1': ("Свой список CIDR", 'cidr.txt', 1),
        '2': ("Свой список IP", 'ip.txt', 2),
        '3': ("UFO", 'cidr_ufo.txt', 1),
        '4': ("Selectel", 'cidr_selectel.txt', 1),
        '5': ("Cloud.ru", 'cidr_cloudru.txt', 1),
        '6': ("Yandex", 'cidr_yandex.txt', 1),
        '7': ("VK", 'cidr_vk.txt', 1),
        '8': ("Reg.ru", 'cidr_regru.txt', 1)
    }
    while True:
        print("Выберите списки для проверки:")
        for k, v in options.items():
            print(f"{k} - {v[0]} ({v[1]})")
        mode_val = input("Ваш выбор [1]: ").strip()
        if not mode_val:
            mode_val = '1'
        if mode_val in options:
            selected_option = options[mode_val]
            filename = selected_option[1]
            mode = selected_option[2]
            break
        print("Пожалуйста, введите число от 1 до 8.\n")
    
    target_file = os.path.join(work_dir, filename)
    if not os.path.exists(target_file):
        fallback_file = os.path.join(script_dir, filename)
        if os.path.exists(fallback_file):
            target_file = fallback_file
        else:
            print(f"Ошибка: Файл {filename} не найден ни в текущей папке ({work_dir}), ни в системной ({script_dir}).")
            sys.exit(1)
            
    results_file = os.path.join(work_dir, "results.csv")
        
    print("\n--- Настройки проверки сети ---")
    if mode == 1:
        num_ips = get_int_input("Сколько IP проверять для каждого CIDR?", 5)
    else:
        num_ips = 1
    timeout = get_int_input("Timeout для ping в секундах?", 2)
    max_threads = get_int_input("Сколько потоков использовать?", 20)
    check_asn = get_yes_no_input("Отображать ASN и провайдера? (y/n) (может не работать при блокировках)", "y")
    save_res = get_yes_no_input(f"Сохранять результаты в {results_file} (y/n)?", "y")
    print("-------------------------------\n")

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

    print(f"{'CIDR/IP':<18} | {'ASN':<12} | {'Provider':<25} | {'PING'}")
    print("-" * 68)

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
                    
                    if save_res:
                        results.append([res_cidr, asn, provider, ping_status])
                        
                except Exception as exc:
                    print(f"{cidr_str:<18} | {'Error':<12} | {'--':<25} | \033[91merror\033[0m")
                    
    except KeyboardInterrupt:
        print('\n[!] Прервано пользователем (Ctrl+C). Выход...')
        os._exit(0)
    except Exception as e:
        print(f"\nОшибка при обработке: {e}")

    # Сохранение результатов
    if save_res and results:
        try:
            with open(results_file, "w", newline='', encoding="utf-8") as cf:
                writer = csv.writer(cf)
                writer.writerow(["CIDR_OR_IP", "ASN", "PROVIDER", "PING"])
                writer.writerows(results)
            print(f"\n[+] Результаты успешно сохранены в {results_file}")
        except Exception as e:
            print(f"\n[-] Ошибка при сохранении результатов: {e}")

if __name__ == '__main__':
    main()
