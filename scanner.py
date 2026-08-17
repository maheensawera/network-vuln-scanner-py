import nmap
import json
import requests
import time
from datetime import datetime

TARGET = "192.168.56.102"

def check_cve(product, version):
    if not product or not version:
        return []
    query = f"{product} {version}"
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {"keywordSearch": query, "resultsPerPage": 3}
    try:
        r = requests.get(url, params=params, timeout=10)
        data = r.json()
        cves = [item['cve']['id'] for item in data.get('vulnerabilities', [])]
        return cves
    except Exception:
        return []

def run_scan(target):
    nm = nmap.PortScanner()
    print(f"[*] Scanning {target} ... please wait")
    nm.scan(target, arguments='-sV')

    results = {
        "target": target,
        "scan_time": str(datetime.now()),
        "hosts": []
    }

    for host in nm.all_hosts():
        host_data = {
            "ip": host,
            "state": nm[host].state(),
            "open_ports": []
        }
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]
                product = service.get('product', '')
                version = service.get('version', '')

                print(f"[*] Checking CVEs for {product} {version} (port {port})...")
                cves = check_cve(product, version)
                time.sleep(1)  # avoid hitting NVD rate limit

                host_data["open_ports"].append({
                    "port": port,
                    "protocol": proto,
                    "service": service.get('name', ''),
                    "product": product,
                    "version": version,
                    "cves": cves
                })
        results["hosts"].append(host_data)

    return results

if __name__ == "__main__":
    data = run_scan(TARGET)

    with open("scan_results.json", "w") as f:
        json.dump(data, f, indent=4)

    print("[+] Scan complete! Results saved to scan_results.json")
    print(json.dumps(data, indent=4))
