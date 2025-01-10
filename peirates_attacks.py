#!/usr/bin/env python3
import os
import pexpect
import time

LOG_DIR = "/usr/local/bin/logs"
os.makedirs(LOG_DIR, exist_ok=True)

MAIN_LOG_FILE = os.path.join(LOG_DIR, "peirates_results.log")
PASS_LOG_FILE = os.path.join(LOG_DIR, "peirates_passed.log")

def log_message(message, log_file=MAIN_LOG_FILE):
    print(message)
    with open(log_file, "a") as f:
        f.write(message + "\n")

def restart_peirates():
    log_message("[+] Restarting Peirates...")
    return pexpect.spawn("peirates", timeout=120)

def safe_decode(data):
    return data.decode() if data else ""

def execute_peirates_commands():
    try:
        child = restart_peirates()
        time.sleep(3) 

        commands = [
            {"option": "22", "name": "Exec via API", "vector": "Exec into container", "post_processing": None},
            {
                "option": "23",
                "name": "Exploit CVE-2024-21626",
                "vector": "Host Shell Access",
                "post_processing": lambda child, name, vector: handle_host_shell_exploit(child, name, vector),
            },
            {
                "option": "12",
                "name": "Access Metadata API",
                "vector": "Instance Metadata API",
                "post_processing": lambda child, name, vector: handle_generic_analysis(child, name, vector, "failed"),
            },
            {
                "option": "30",
                "name": "Steal Secrets from Node Filesystem",
                "vector": "List K8S Secrets",
                "post_processing": lambda child, name, vector: handle_generic_analysis(child, name, vector, "path does not exist"),
            },
        ]

        for cmd in commands:
            log_message(f"[+] Running command: {cmd['name']} ({cmd['vector']})")
            child.sendline(cmd["option"])
            time.sleep(3) 

            result = safe_decode(child.before)
            if cmd["post_processing"]:
                cmd["post_processing"](child, cmd["name"], cmd["vector"])
            else:
                analyze_result(cmd["name"], cmd["vector"], result)

            child.sendline("")  
            time.sleep(2)

     
            if cmd["option"] == "22":
                child.close()
                child = restart_peirates()
                time.sleep(3)

        child.sendline("exit") 
        child.close()
        log_message("[+] Peirates execution completed.")

    except pexpect.exceptions.TIMEOUT:
        log_message("[-] Error: Timeout while interacting with Peirates.")
    except Exception as e:
        log_message(f"[-] Error: Unexpected exception occurred: {e}")

def analyze_result(command_name, vector, result):
    if not result:
        log_message(f"[FAIL] {command_name} exploitation failed.")
    elif "failed" in result.lower() or "refused" in result.lower() or "error" in result.lower():
        log_message(f"[FAIL] {command_name} exploitation failed:\n{result}")
    else:
        log_message(f"[PASS] {command_name} ({vector}) exploitation succeeded.")
        log_message(f"[PASS] {command_name} ({vector}) exploitation succeeded.", log_file=PASS_LOG_FILE)


def handle_host_shell_exploit(child, command_name, vector):
    try:
        time.sleep(3)  
        result = safe_decode(child.before)
        if "permission denied" in result.lower():
            log_message(f"[FAIL] {command_name} exploitation failed: insufficient permissions.")
        else:
            analyze_result(command_name, vector, result)
    except Exception as e:
        log_message(f"[-] Error during Host Shell Exploit handling: {e}")

def handle_generic_analysis(child, command_name, vector, fail_message):
    try:
        time.sleep(3)  
        result = safe_decode(child.before)
        if fail_message in result.lower():
            log_message(f"[FAIL] {command_name} ({vector}) exploitation failed: {fail_message}.")
        else:
            analyze_result(command_name, vector, result)
    except Exception as e:
        log_message(f"[-] Error during analysis: {e}")

if __name__ == "__main__":
    log_message("[+] Starting Peirates automation...")
    execute_peirates_commands()
    log_message(f"Peirates automation finished. Logs saved to {MAIN_LOG_FILE}.")

