from core.recon_core import run_recon
from ai_engine.payload_suggestions import suggest_payloads
from reports.report_generator import generate_report

def main():

    domain = input("Enter target domain: ")

    print("\n[+] Running FULL AI Recon Engine...\n")

    results = run_recon(domain)

    # Extract results
    subdomains = results.get("subdomains", [])
    alive_hosts = results.get("live_hosts", [])
    endpoints = results.get("important_urls", [])
    findings = results.get("findings", [])
    risk = results.get("risk", {})

    # PRINT RESULTS
    print("\n===== RESULTS =====")

    print("\n[Subdomains]")
    for sub in subdomains:
        print(sub)

    print("\n[Alive Hosts]")
    for host in alive_hosts:
        print(host["url"])

    print("\n[Endpoints]")
    for ep in endpoints[:50]:   # limit output
        print(ep)

    print("\n[Findings]")
    for f in findings:
        if isinstance(f, dict):
            print(f"[{f.get('type')}] {f.get('url')}")
        else:
            print(f)

    # Suggest payloads (still useful)
    from ai_engine.payload_suggestions import suggest_payloads
    suggest_payloads(findings)

    # Generate report
    from reports.report_generator import generate_report
    generate_report(domain, alive_hosts, endpoints, findings, risk)
        
if __name__ == "__main__":
    main()
