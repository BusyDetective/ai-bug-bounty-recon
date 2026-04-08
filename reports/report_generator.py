import os

def generate_report(domain, alive_hosts, endpoints, findings, risk):
    base_dir = os.path.dirname(os.path.abspath(__file__))
    filename = os.path.join(base_dir, f"{domain}_report.txt")

    with open(filename, "w") as f:
        f.write(f"Recon Report for {domain}\n")
        f.write("="*50 + "\n\n")

        f.write("Alive Hosts:\n")
        for host in alive_hosts:
            f.write(f"{host['url']}\n")

        f.write("\nEndpoints:\n")
        for ep in endpoints:
            f.write(f"{ep}\n")

        f.write("\nFindings:\n")
        for vuln, url in findings:
            f.write(f"{vuln} → {url}\n")

        f.write("\nRisk Summary:\n")
        f.write(f"High Risk:\n")
        for h in risk["high"]:
            f.write(f"{h}\n")

        f.write("\nMedium Risk:\n")
        for m in risk["medium"]:
            f.write(f"{m}\n")

        f.write("\nLow Risk:\n")
        for l in risk["low"]:
            f.write(f"{l}\n")

    print(f"\n[+] Report saved as {filename}")
