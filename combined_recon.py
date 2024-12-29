#!/usr/bin/env python3
import subprocess
import os
from datetime import datetime

LOG_DIR = "/usr/local/bin/logs"
os.makedirs(LOG_DIR, exist_ok=True)

# Матрица MITRE и значения уязвимостей
MITRE_MATRIX = {
    "Initial Access": {"Compromised image in registry": 2},
    "Execution": {
        "Exec into container": 2,
        "Bash/cmd inside container": 2,
        "New container": 3,
        "SSH server running inside container": 3,
        "Sidecar injection": 2,
    },
    "Persistence": {
        "Backdoor container": 3,
        "Writable hostPath mount": 3,
        "Container service account": 2,
    },
    "Privilege Escalation": {
        "Privileged container": 3,
        "Cluster-admin binding": 3,
        "HostPath mount": 3,
        "Access cloud resources": 3,
    },
    "Defense Evasion": {"Connect from proxy server": 1},
    "Credential Access": {
        "List K8S secrets": 3,
        "Mount service principal": 3,
        "Container service account": 2,
    },
    "Discovery": {
        "Access Kubernetes API server": 3,
        "Access Kubelet API": 3,
        "Network mapping": 2,
        "Instance Metadata API": 3,
    },
    "Lateral Movement": {
        "Container service account": 2,
        "Cluster internal networking": 2,
        "Writable hostPath mount": 3,
        "ARP poisoning and IP spoofing": 2,
    },
    "Collection": {"Collecting data from pod": 2},
}

scripts = [
    "network_mapping.py",
    "access_kubelet_api.py",
    "access_kubernetes_api.py",
    "credintial_access.py",
    "kube_bench_scan.py"
]

def run_script(script_path):
    print(f"[+] Running script: {script_path}")
    try:
        result = subprocess.run(["python3", script_path], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"[-] Error while running {script_path}: {e}")
        if 'result' in locals():
            print(result.stderr if result.stderr else "No output captured.")

def evaluate_vulnerabilities():
    print("[+] Evaluating vulnerabilities...")
    found_vulnerabilities = {}

    # Открываем логи и ищем маркеры
    log_files = [f for f in os.listdir(LOG_DIR) if f.endswith(".log")]
    for log_file in log_files:
        log_path = os.path.join(LOG_DIR, log_file)
        print(f"[+] Analyzing log file: {log_file}")
        try:
            with open(log_path, "r") as f:
                content = f.read()
                for category, vectors in MITRE_MATRIX.items():
                    for vector, score in vectors.items():
                        if vector in content:  # Проверяем наличие маркера
                            if category not in found_vulnerabilities:
                                found_vulnerabilities[category] = {}
                            found_vulnerabilities[category][vector] = score
        except Exception as e:
            print(f"[-] Error reading log file {log_file}: {e}")
            continue

    return found_vulnerabilities

def generate_report(found_vulnerabilities):
    print("[+] Generating final report...")
    total_score = 0
    total_vulnerabilities = 0
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    report_path = os.path.join(LOG_DIR, "final_report.txt")
    with open(report_path, "w") as report:
        report.write("Kubernetes Security Assessment Report\n")
        report.write(f"Report generated at: {timestamp}\n")
        report.write("=" * 50 + "\n\n")

        for category, vectors in found_vulnerabilities.items():
            report.write(f"{category}:\n")
            for vector, score in vectors.items():
                report.write(f"  - {vector}: Risk Level {score}\n")
                total_score += score
                total_vulnerabilities += 1
            report.write("\n")

        report.write("=" * 50 + "\n")
        report.write(f"Total Vulnerabilities: {total_vulnerabilities}\n")
        report.write(f"Aggregate Risk Score: {total_score}\n")

    print(f"[+] Report saved to {report_path}")

if __name__ == "__main__":
    print("[+] Starting MITRE Techniques assessment...\n")
    for script in scripts:
        if os.path.exists(script):
            run_script(script)
        else:
            print(f"[-] Script not found: {script}")

    # Оценка и генерация отчета
    found_vulnerabilities = evaluate_vulnerabilities()
    generate_report(found_vulnerabilities)
    print("[+] Assessment completed.")
    print("[+] Please, also check final report file for information about possible vulnerabilities and best practices by Kubernetes CIS Matrix")

