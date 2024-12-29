#!/usr/bin/env python3
import os
import subprocess
import json

LOG_DIR = "/usr/local/bin/logs"
os.makedirs(LOG_DIR, exist_ok=True)

TARGETS = ["master", "node", "controlplane", "etcd", "policies"]  # Возможные цели

def run_kube_bench(target):
    command = f"kube-bench run --json --targets {target}"
    try:
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT).decode("utf-8")
        return output
    except subprocess.CalledProcessError as e:
        print(f"Error running kube-bench for target {target}: {e.output.decode('utf-8')}")
        return None

def parse_results(target, json_output):
    log_file = os.path.join(LOG_DIR, f"kube_bench_{target}.log")
    results = json.loads(json_output)
    fail_count = 0
    warn_count = 0
    with open(log_file, "w") as log:
        log.write(f"Target: {target}\n")
        log.write(f"{'-'*50}\n")
        for control in results.get("Controls", []):
            for test in control.get("tests", []):
                for result in test.get("results", []):
                    status = result.get("status")
                    if status in ["FAIL", "WARN"]:
                        log.write(f"Test {result.get('test_number')}:\n")
                        log.write(f"Description: {result.get('test_desc')}\n")
                        log.write(f"Status: {status}\n")
                        log.write(f"Remediation: {result.get('remediation', 'N/A')}\n")
                        log.write(f"{'-'*50}\n")
                        if status == "FAIL":
                            fail_count += 1
                        elif status == "WARN":
                            warn_count += 1
        log.write(f"\nSummary for {target}:\n")
        log.write(f"Total WARN: {warn_count}\n")
        log.write(f"Total FAIL: {fail_count}\n")
    return fail_count, warn_count

def main():
    total_fail = 0
    total_warn = 0
    for target in TARGETS:
        print(f"Scanning target: {target}...")
        json_output = run_kube_bench(target)
        if json_output:
            fail_count, warn_count = parse_results(target, json_output)
            total_fail += fail_count
            total_warn += warn_count
    summary_log = os.path.join(LOG_DIR, "kube_bench_summary.log")
    with open(summary_log, "w") as summary:
        summary.write("Kube-Bench Scan Summary\n")
        summary.write(f"{'-'*50}\n")
        summary.write(f"Total WARN: {total_warn}\n")
        summary.write(f"Total FAIL: {total_fail}\n")
   
    print(f"Scanning completed. Possible vulnerabilities and best practices are logged in {LOG_DIR}")
    print(f"Summary: Total WARN: {total_warn}, Total FAIL: {total_fail}")

if __name__ == "__main__":
    main()

