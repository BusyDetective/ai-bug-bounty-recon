from flask import Flask, render_template, request, send_file
import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.subdomain_enum import enumerate_subdomains
from core.alive_check import check_alive
from core.endpoint_finder import find_endpoints
from ai_engine.vuln_patterns import detect_vuln_patterns
from ai_engine.risk_scoring import calculate_risk

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    domain = request.form.get('domain')

    subdomains = enumerate_subdomains(domain)
    alive_hosts = check_alive(subdomains)
    endpoints = find_endpoints(alive_hosts)
    findings = detect_vuln_patterns(endpoints)
    risk = calculate_risk(endpoints, alive_hosts)

    return render_template(
        'results.html',
        domain=domain,
        subdomains=subdomains,
        alive_hosts=alive_hosts,
        endpoints=endpoints,
        findings=findings,
        risk=risk
    )

@app.route('/download/<domain>')
def download_report(domain):
    safe_domain = domain.replace(".", "_")
    filename = f"{safe_domain}_report.txt"

    # Get full path to project root
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    file_path = os.path.join(base_dir, filename)

    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return f"File not found: {file_path}"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)