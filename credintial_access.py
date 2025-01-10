#!/usr/bin/env python3
import os
import subprocess

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

def check_k8s_secrets():
    print("[+] Checking access to Kubernetes secrets...")
    kubectl_command = "kubectl get secrets --all-namespaces"
    kubectl_output = run_command(kubectl_command)
    write_to_log(os.path.join(LOG_DIR, "k8s_secrets.log"), kubectl_output)

    if "Error" not in kubectl_output and "NAME" in kubectl_output:
        print("[PASS] List K8S secrets: Exploited")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[PASS] List K8S secrets: Exploited")
    else:
        print("[-] Unable to access Kubernetes secrets.")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[FAIL] List K8S secrets: Not exploitable")

def check_service_account_token():
    print("[+] Checking container service account via kdigger...")
    kdigger_command = "kdigger dig all"
    kdigger_output = run_command(kdigger_command)
    write_to_log(os.path.join(LOG_DIR, "kdigger_service_account.log"), kdigger_output)

    if "A service account token is mounted" in kdigger_output:
        print("[PASS] Container service account: Exploited")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[PASS] Container service account: Exploited")
    else:
        print("[-] No service account token detected via kdigger.")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[FAIL] Container service account: Not exploitable")

def analyze_instance_metadata():
    print("[+] Checking for Instance Metadata API...")
    botb_command = "botb -metadata"
    botb_output = run_command(botb_command)
    write_to_log(os.path.join(LOG_DIR, "botb_metadata.log"), botb_output)

    if "Response from" in botb_output and "403" in botb_output:
        print("[-] Instance Metadata API not exploitable.")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[FAIL] Instance Metadata API: Not exploitable")
    elif "Response from" in botb_output and "200" in botb_output:
        print("[PASS] Instance Metadata API: Successfully accessed.")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[PASS] Instance Metadata API: Successfully accessed.")
    else:
        print("[-] Instance Metadata API not exploitable.")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[FAIL] Instance Metadata API: Not exploitable")

def check_mount_service_principal():
    print("[+] Checking for mounted service principal credentials...")
    botb_command = "botb -find-http"
    botb_output = run_command(botb_command)
    write_to_log(os.path.join(LOG_DIR, "botb_service_principal.log"), botb_output)

    if "HTTP socket found" in botb_output:
        print("[PASS] Mounted service principal credentials: Exploited")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[PASS] Mounted service principal credentials: Exploited")
    else:
        print("[-] BOtB did not detect mounted service principal credentials.")
        write_to_log(os.path.join(LOG_DIR, "attack_log.log"), "[FAIL] Mounted service principal credentials: Not exploitable")

def evaluate_credential_access():
    print("[+] Evaluating credential access attack vectors...")
    results = []
    log_files = [
        "botb_k8secrets.log",
        "kdigger_service_account.log",
        "botb_metadata.log",
        "botb_service_principal.log"
    ]
    for log_file in log_files:
        log_path = os.path.join(LOG_DIR, log_file)
        with open(log_path, "r") as f:
            results.append(f.read())

    final_log = os.path.join(LOG_DIR, "credential_access_results.log")
    with open(final_log, "w") as f:
        f.write("\n".join(results))
    print("[+] Credential access evaluation completed. Results saved.")

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

