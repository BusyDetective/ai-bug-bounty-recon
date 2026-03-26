from core.subdomain_enum import enumerate_subdomains
from core.alive_check import check_alive
from core.endpoint_finder import find_endpoints
from ai_engine.vuln_patterns import detect_vuln_patterns
from ai_engine.risk_scoring import calculate_risk
from ai_engine.payload_suggestions import suggest_payloads
from reports.report_generator import generate_report

def main():

    domain = input("Enter target domain: ")

    subdomains = enumerate_subdomains(domain)

    print("\nDiscovered Subdomains:\n")
    for sub in subdomains:
        print(sub)

    # NEW STEP
    alive_hosts = check_alive(subdomains)

    print("\nAlive Hosts:\n")
    for host in alive_hosts:
        print(host["url"])

    endpoints = find_endpoints(alive_hosts)

    print("\nDiscovered Endpoints:\n")
    for ep in endpoints:
        print(ep)
    
    findings = detect_vuln_patterns(endpoints)

    risk = calculate_risk(endpoints, alive_hosts)

    suggest_payloads(findings)

    generate_report(domain, alive_hosts, endpoints, findings, risk)
        
if __name__ == "__main__":
    main()
