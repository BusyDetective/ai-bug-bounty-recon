import os

def generate_report(domain, alive_hosts, endpoints, findings, risk):
    safe_domain = domain.replace(".", "_")
    filename = f"{safe_domain}_report.txt"

    file_path = os.path.join("reports", filename)

    # ensure folder exists
    os.makedirs("reports", exist_ok=True)

    with open(file_path, "w") as f:
        f.write(f"Recon Report for {domain}\n")
        f.write("="*50 + "\n\n")

        f.write("Alive Hosts:\n")
        for host in alive_hosts:
            f.write(f"{host['url']}\n")

        f.write("\nEndpoints:\n")
        for ep in endpoints:
        if isinstance(ep, dict):
            f.write(f"[{', '.join(ep['tags'])}] {ep['url']}\n")
        else:
            f.write(f"{ep}\n")

        f.write("\nFindings:\n")

        if not findings:
            f.write("No direct vulnerabilities found. Showing high-risk endpoints:\n\n")

            for ep in endpoints[:20]:
                f.write(f"[Interesting] {ep}\n")
        else:
            for v in findings:
                if isinstance(v, dict):
                    f.write(f"{v['type']} → {v['url']}\n")
                else:
                    vuln, url = v
                    f.write(f"{vuln} → {url}\n")

        f.write("\nRisk Summary:\n")
        f.write(f"High Risk:\n")
        for h in risk.get("high", []):
            f.write(f"{h}\n")

        f.write("\nMedium Risk:\n")
        for m in risk.get("medium", []):
            f.write(f"{m}\n")

        f.write("\nLow Risk:\n")
        for l in risk.get("low", []):
            f.write(f"{l}\n")

        f.write("\nTop High-Value Targets:\n")

        for ep in endpoints[:15]:
            f.write(f"{ep}\n")

    print(f"\n[+] Report saved as {filename}")
