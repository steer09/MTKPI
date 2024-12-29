#!/usr/bin/env python3
import os
import subprocess
import json
import requests

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

def check_k8s_secrets():
    """Проверяет доступ к секретам K8s."""
    print("[+] Checking access to Kubernetes secrets...")
    kubectl_output = run_command("kubectl get secrets --all-namespaces")
    write_to_log(os.path.join(LOG_DIR, "k8s_secrets.log"), kubectl_output)
    if "Error" not in kubectl_output:
        print("[+] Access to Kubernetes secrets is available.")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[MTKPI: List K8S secrets Exploited]")
    else:
        print("[-] Unable to access Kubernetes secrets.")

    # Botb for secrets
    botb_output = run_command("botb -k8secrets")
    write_to_log(os.path.join(LOG_DIR, "botb_k8secrets.log"), botb_output)
    if "Token found" in botb_output:
        print("[+] Botb found Kubernetes secrets.")
    else:
        print("[-] Botb did not find Kubernetes secrets.")

def check_service_account_token():
    print("[+] Checking container service account via kdigger...")
    kdigger_output = run_command("kdigger dig all")
    write_to_log(os.path.join(LOG_DIR, "kdigger_service_account.log"), kdigger_output)
    if "token" in kdigger_output.lower():
        print("[+] Service account token found via kdigger.")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[MTKPI: Container service account Exploited]")
    else:
        print("[-] No service account token detected via kdigger.")

def analyze_instance_metadata():
    print("[+] Checking for Instance Metadata API...")
    botb_output = run_command("botb -metadata")
    write_to_log(os.path.join(LOG_DIR, "botb_metadata.log"), botb_output)

    accessible = False
    results = []
    for line in botb_output.splitlines():
        if "Reponse from" in line and "200" in line:
            accessible = True
            results.append(f"[+] Metadata API successfully accessed: {line}")
        elif "Reponse from" in line:
            results.append(f"[-] Metadata API access denied: {line}")

    if accessible:
        print("[+] Instance Metadata API successfully accessed.")
    else:
        print("[-] Instance Metadata API not exploitable.")

def check_mount_service_principal():
    print("[+] Checking for mounted service principal credentials...")

    botb_output = run_command("botb -find-http")
    write_to_log(os.path.join(LOG_DIR, "botb_service_principal.log"), botb_output)
    if "HTTP socket found" in botb_output:
        print("[+] BOtB detected mounted service principal credentials.")
        #write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[MTKPI: Mount service principal Exploited]")
    else:
        print("[-] BOtB did not detect mounted service principal credentials.")


    kdigger_output = run_command("kdigger dig all")
    write_to_log(os.path.join(LOG_DIR, "kdigger_service_principal.log"), kdigger_output)
    if "principal" in kdigger_output.lower() or "service" in kdigger_output.lower():
        print("[+] Kdigger detected mounted service principal credentials.")
    else:
        print("[-] Kdigger did not detect mounted service principal credentials.")

def evaluate_credential_access():"
    print("[+] Evaluating credential access attack vectors...")
    results = []

    # Check secrets
    with open(os.path.join(LOG_DIR, "botb_k8secrets.log")) as f:
        if "Token found" in f.read():
            results.append("[+] Access to K8s secrets successfully exploited.")
            write_to_log(os.path.join(LOG_DIR, "k8secrets_log.log"), f"[MTKPI: List K8S secrets Exploited]")
        else:
            results.append("[-] Access to K8s secrets not exploitable.")

    with open(os.path.join(LOG_DIR, "kdigger_service_account.log")) as f:
        if "token" in f.read().lower():
            results.append("[+] Service account token successfully identified.")
        else:
            results.append("[-] Service account token not exploitable.")

    # Check metadata API
    with open(os.path.join(LOG_DIR, "botb_metadata.log")) as f:
        metadata_results = f.read()
        if "successfully accessed" in metadata_results:
            results.append("[+] Instance Metadata API successfully accessed.")
            write_to_log(os.path.join(LOG_DIR, "botb_result_metadata.log"), f"[MTKPI: Instance Metadata API Exploited]")
        else:
            results.append("[-] Instance Metadata API not exploitable.")


    with open(os.path.join(LOG_DIR, "botb_service_principal.log")) as f1, open(os.path.join(LOG_DIR, "kdigger_service_principal.log")) as f2:
        botb_results = f1.read()
        kdigger_results = f2.read()
        if "HTTP socket found" in botb_results or "principal" in kdigger_results.lower():
            results.append("[+] Mounted service principal credentials successfully detected.")
            write_to_log(os.path.join(LOG_DIR, "service_principal.log"), "[MTKPI: Mount service principal Exploited]")
        else:
            results.append("[-] Mounted service principal credentials not exploitable.")

    final_log = os.path.join(LOG_DIR, "credential_access_results.log")
    with open(final_log, "w") as f:
        f.write("\n".join(results))
    print("[+] Credential access evaluation completed. Results saved.")
    for line in results:
        print(line)

def strict_credential_access():
    print("[+] Starting strict credential access reconnaissance...")
    check_k8s_secrets()
    check_service_account_token()
    analyze_instance_metadata()
    check_mount_service_principal()
    evaluate_credential_access()
    print("[+] Credential access phase completed.")

if __name__ == "__main__":
    strict_credential_access()

