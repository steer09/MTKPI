#!/usr/bin/env python3
import os
import subprocess
import re
import json

LOG_DIR = "/usr/local/bin/logs"
os.makedirs(LOG_DIR, exist_ok=True)

def write_to_log(filename, content):
    with open(filename, "w") as log_file:
        log_file.write(content + "\n")

def run_command(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode("utf-8")
        return output
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode('utf-8')}"

def kubectl_network_mapping():
    print("[+] Running kubectl for network mapping...")
    kubectl_commands = {
        "pods_info": "kubectl get pods -o wide --all-namespaces",
        "services_info": "kubectl get services -o wide --all-namespaces",
        "networkpolicies_info": "kubectl get networkpolicies --all-namespaces",
        "secrets_info": "kubectl get secrets --all-namespaces",
        "configmaps_info": "kubectl get configmaps --all-namespaces",
        "nodes_info": "kubectl get nodes -o wide",
    }
    for name, command in kubectl_commands.items():
        output = run_command(command)
        write_to_log(os.path.join(LOG_DIR, f"{name}.log"), output)
        print(f"[+] {name.replace('_', ' ').capitalize()} saved to logs.")

def run_deepce():
    print("[+] Running deepce...")
    command = "deepce -q"
    output = run_command(command)
    write_to_log(os.path.join(LOG_DIR, "deepce.log"), output)
    print("[+] Deepce output saved to logs.")

    # Парсим вывод для Attempting Ping Sweep и Scanning Host
    ping_sweep_ips = re.findall(r"Host: (\d+\.\d+\.\d+\.\d+)", output)
    scanning_ports = re.findall(r"Open port: (\d+)", output)
    if ping_sweep_ips:
        write_to_log(os.path.join(LOG_DIR, "ping_sweep_ips.log"), "\n".join(ping_sweep_ips))
        print(f"[+] Found active IPs from Deepce: {ping_sweep_ips}")
    if scanning_ports:
        write_to_log(os.path.join(LOG_DIR, "open_ports.log"), "\n".join(scanning_ports))
        print(f"[+] Found open ports from Deepce: {scanning_ports}")

def run_kube_hunter(ip_list):
    print("[+] Running kube-hunter...")
    if not ip_list:
        print("[-] No IPs provided for kube-hunter. Skipping...")
        write_to_log(os.path.join(LOG_DIR, "kube_hunter.log"), "No IPs provided for kube-hunter.")
        return

    ips = ",".join(ip_list)
    command = f"python3 -m kube_hunter --active --remote {ips} --log debug"
    output = run_command(command)
    write_to_log(os.path.join(LOG_DIR, "kube_hunter.log"), output)
    if "No vulnerabilities were found" in output:
        print("[+] No vulnerabilities found by kube-hunter.")
    else:
        print("[+] Vulnerabilities found by kube-hunter. Check logs for details.")

def evaluate_network_mapping():
    print("[+] Evaluating network mapping results...")
    results = []

    # Проверка данных о подах, сервисах и политиках
    for resource in ["pods_info", "services_info", "networkpolicies_info"]:
        file_path = os.path.join(LOG_DIR, f"{resource}.log")
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                data = f.read()
            if "Error" not in data:
                results.append(f"[+] {resource.replace('_', ' ').capitalize()} retrieved successfully.")

    ping_sweep_file = os.path.join(LOG_DIR, "ping_sweep_ips.log")
    ports_file = os.path.join(LOG_DIR, "open_ports.log")
    if os.path.exists(ping_sweep_file):
        with open(ping_sweep_file, "r") as f:
            active_ips = f.read().strip().split("\n")
        results.append(f"[+] Active IPs from Deepce: {', '.join(active_ips)}")
    if os.path.exists(ports_file):
        with open(ports_file, "r") as f:
            open_ports = f.read().strip().split("\n")
        results.append(f"[+] Open ports from Deepce: {', '.join(open_ports)}")

    final_log = os.path.join(LOG_DIR, "network_mapping_results.log")
    with open(final_log, "w") as f:
        f.write("\n".join(results))
    print("[+] Network mapping evaluation completed. Results saved to network_mapping_results.log.")

def strict_network_mapping():
    print("[+] Starting strict network mapping reconnaissance...")
    kubectl_network_mapping()

    # Сканируем узлы, найденные через kubectl
    internal_ips = []
    try:
        kubectl_nodes_output = run_command("kubectl get nodes -o json")
        nodes_data = json.loads(kubectl_nodes_output)
        for item in nodes_data.get("items", []):
            for address in item.get("status", {}).get("addresses", []):
                if address.get("type") == "InternalIP":
                    internal_ips.append(address.get("address"))
        print(f"[+] Found internal IPs: {internal_ips}")
    except Exception as e:
        print(f"[-] Error retrieving node information: {e}")

    run_deepce()
    if internal_ips:
        run_kube_hunter(internal_ips)

    evaluate_network_mapping()
    print("[+] Network mapping phase completed.")

if __name__ == "__main__":
    strict_network_mapping()

