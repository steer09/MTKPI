#!/usr/bin/env python3
import os
import subprocess

LOG_DIR = "/usr/local/bin/logs"
os.makedirs(LOG_DIR, exist_ok=True)

RESOURCES = [
    "pods",
    "secrets",
    "configmaps",
    "services",
    "nodes"
]

def write_to_log(filename, content):
    with open(filename, "a") as log_file:
        log_file.write(content + "\n")

def run_command(command):
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode("utf-8")
        return output
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode('utf-8')}"

def check_kubernetes_api_access():
    print("[+] Checking access to Kubernetes API Server...")
    access_results = {}

    for resource in RESOURCES:
        print(f"[+] Checking access to {resource}...")
        command = f"kubectl get {resource} --all-namespaces"
        output = run_command(command)

        log_filename = os.path.join(LOG_DIR, f"kubernetes_api_{resource}.log")
        write_to_log(log_filename, output)

        if "Forbidden" in output:
            print(f"[-] Access to {resource} is forbidden.")
            access_results[resource] = "Forbidden"
        elif "No resources found" in output:
            print(f"[+] Access to {resource} is allowed but no resources found.")
            access_results[resource] = "Allowed (no resources)"
        else:
            print(f"[+] Access to {resource} is allowed and resources are available.")
            access_results[resource] = "Allowed (resources available)"

    return access_results

def evaluate_attack_applicability(access_results):
    print("[+] Evaluating attack applicability...")
    write_to_log(os.path.join(LOG_DIR, "attack_evaluation.log"), "[+] Evaluating attack applicability...")

    if "Forbidden" not in access_results.values():
        print("[+] Access Kubernetes API Server exploited. Attack vector successfully applicable.") 
        write_to_log(os.path.join(LOG_DIR, "access_kubapi.log"), f"[MTKPI: Access Kubernetes API Exploited]")
        return "Successfully exploited"
    else:
        print("[-] Access to some resources is forbidden. Attack vector partially applicable.")
        write_to_log(os.path.join(LOG_DIR, "attack_evaluation.log"), "Access to some resources is forbidden. Attack vector partially applicable.")
        return "Partially applicable"

def strict_recon():
    print("[+] Starting strict reconnaissance for Kubernetes API Server...")
    write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[+] Starting strict reconnaissance for Kubernetes API Server...")

    access_results = check_kubernetes_api_access()
    write_to_log(os.path.join(LOG_DIR, "attack_log.log"), f"Access results: {access_results}")

    attack_status = evaluate_attack_applicability(access_results)
    write_to_log(os.path.join(LOG_DIR, "attack_log.log"), f"Attack status: {attack_status}")

    print("[+] Access Kubernetes  API phase completed.")
    write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[+] Reconnaissance completed.")

if __name__ == "__main__":
    strict_recon()

