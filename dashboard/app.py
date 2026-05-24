from flask import Flask, render_template, request, send_file, redirect, session
import sys
import os
os.environ["CLI_MODE"] = "0"
import matplotlib.pyplot as plt
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.recon_core import run_recon
from ai_engine.risk_scoring import calculate_risk
from database import (
    init_db,
    save_scan,
    get_scans,
    create_user,
    authenticate_user
)

app = Flask(__name__)
app.secret_key = "supersecretkey"
init_db()

@app.route('/')
def index():

    if "user" not in session:
        return redirect("/login")

    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():

    if "user" not in session:
        return redirect("/login")

    domain = request.form.get('domain')

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

    results = run_recon(domain)
    save_scan(
        domain,
        results["risk"],
        results["findings"]
    )

    subdomains = results.get("subdomains", [])
    alive_hosts = results.get("live_hosts", [])
    endpoints = results.get("endpoints", [])
    findings = results.get("findings", [])
    verified = results.get("verified", [])
    exploits = results.get("exploits", [])
    validated_exploits = results.get("validated_exploits", [])
    priorities = results.get("priorities", [])

    risk = results.get("risk", {"high": [], "medium": [], "low": []})

    # Prepare data
    labels = ['High', 'Medium', 'Low']
    sizes = [
        len(risk.get('high', [])),
        len(risk.get('medium', [])),
        len(risk.get('low', []))
    ]

    if sum(sizes) == 0:
        sizes = [0.1, 0.1, 0.1]  # prevent empty pie crash

    colors = ['#ef4444', '#f59e0b', '#22c55e']

    # Create chart
    plt.figure(figsize=(4,4))
    wedges, texts, autotexts = plt.pie(
        sizes,
        colors=colors,
        autopct='%1.0f%%',
        startangle=90
    )

    plt.legend(wedges, labels, loc="upper right", fontsize=8)
    plt.axis('equal')
    plt.title('Risk Distribution', fontsize=10)

    chart_path = os.path.join(os.getcwd(), "chart.png")
    plt.savefig(chart_path)
    plt.close()

    # Generate report content
    safe_domain = (
        domain
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(".", "_")
    )
    filename = f"{safe_domain}_report.pdf"

    file_path = os.path.join(os.getcwd(), filename)

    styles = getSampleStyleSheet()
    from reportlab.lib.enums import TA_CENTER

    styles['Title'].alignment = TA_CENTER
    doc = SimpleDocTemplate(file_path)

    content = []

    # Title
    content.append(Paragraph("<b>AI Reconnaissance Security Assessment Report</b>", styles['Title']))
    content.append(Spacer(1, 5))
    content.append(Paragraph("<font size=10>Automated Reconnaissance & Risk Analysis</font>", styles['Normal']))
    content.append(Spacer(1, 15))
    content.append(Spacer(1, 10))
    content.append(Paragraph(f"Target: {domain}", styles['Normal']))
    content.append(Spacer(1, 20))

    content.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    content.append(Spacer(1, 10))

    # Subdomains
    content.append(Paragraph("<b>🔹 Subdomains</b>", styles['Heading2']))
    for sub in subdomains:
        content.append(Paragraph(sub, styles['Normal']))
    content.append(Spacer(1, 10))

    # Alive Hosts
    content.append(Paragraph("<b>🔹 Alive Hosts</b>", styles['Heading2']))
    for host in alive_hosts:
        content.append(
            Paragraph(f"{host['url']} | {host['status']} | {host['title']}", styles['Normal'])
        )
    content.append(Spacer(1, 10))

    # Endpoints
    content.append(Paragraph("<b>🔹 Endpoints</b>", styles['Heading2']))
    for ep in endpoints:
        if isinstance(ep, dict):
            content.append(
                Paragraph(f"[{', '.join(ep['tags'])}] {ep['url']}", styles['Normal'])
            )
        else:
            content.append(Paragraph(str(ep), styles['Normal']))
    content.append(Spacer(1, 10))

    # Findings
    content.append(Paragraph("<b>🔹 Findings</b>", styles['Heading2']))
    for v in findings:
        if isinstance(v, dict):
            severity = v.get("severity", "Low")   # 🔥 SAFE FIX
            vuln_type = v.get("type", "Unknown")
            url = v.get("url", "N/A")

            impact = {
                "XSS": "Can execute malicious scripts in user browser",
                "OPEN_REDIRECT": "Can redirect users to malicious websites",
                "SQLI": "Can expose or manipulate database data"
            }

            fix = {
                "XSS": "Sanitize user input and escape output",
                "OPEN_REDIRECT": "Validate redirect URLs",
                "SQLI": "Use parameterized queries"
            }

            content.append(
                Paragraph(
                    f"[{severity}] {vuln_type} → {url}<br/>"
                    f"<b>Impact:</b> {impact.get(vuln_type, 'Unknown')}<br/>"
                    f"<b>Fix:</b> {fix.get(vuln_type, 'Manual review required')}",
                    styles['Normal']
                )
            )

        else:
            vuln, url = v

            content.append(
                Paragraph(f"[Low] {vuln} → {url}", styles['Normal'])
            )

    content.append(Paragraph("<b>■ Recommendations</b>", styles['Heading2']))

    for v in findings:
        if isinstance(v, dict):
            url = v["url"]
        else:
            url = v[1]

        if any(x in url.lower() for x in ["admin", "login", "auth"]):
            content.append(Paragraph(
                f"Restrict access to admin panel: {url} using authentication and IP filtering.",
                styles['Normal']
            ))
    content.append(Spacer(1, 10))

    # Risk Summary (COLORED)
    content.append(Spacer(1, 30))
    content.append(Paragraph("<b>📊 Risk Distribution Overview</b>", styles['Heading2']))
    content.append(Spacer(1, 20))
    content.append(Paragraph(
        "This chart represents the distribution of identified risks across severity levels.",
        styles['Normal']
    ))
    content.append(Spacer(1, 20))
    content.append(Paragraph(f"<font color='red'>High: {len(risk['high'])}</font>", styles['Normal']))
    content.append(Paragraph(f"<font color='orange'>Medium: {len(risk['medium'])}</font>", styles['Normal']))
    content.append(Paragraph(f"<font color='green'>Low: {len(risk['low'])}</font>", styles['Normal']))
    content.append(Spacer(1, 20))

    content.append(Spacer(1, 10))
    content.append(Paragraph(
        "Severity levels are categorized based on potential impact and exposure. "
        "High-risk findings require immediate attention, while medium and low risks "
        "should be addressed based on priority and context.",
        styles['Normal']
    ))

    content.append(PageBreak())

    # Add Chart Image
    content.append(Paragraph("<b>Risk Distribution Chart</b>", styles['Heading2']))
    content.append(Spacer(1, 10))
    content.append(Image(chart_path, width=250, height=250))

    content.append(Spacer(1, 40))
    content.append(Paragraph(
        "<font size=8>Generated by AI Bug Bounty Recon Tool | For educational purposes only</font>",
        styles['Normal']
    ))
    
    doc.build(content)

    if os.path.exists(chart_path):
        os.remove(chart_path)

    analysis_results = results.get("analysis", [])
    exploits = results.get("exploits", [])

    return render_template(
        'results.html',
        domain=domain,
        subdomains=subdomains,
        alive_hosts=alive_hosts,
        endpoints=endpoints,
        findings=findings,
        risk=risk,
        analysis_results=analysis_results,
        verified=verified,
        exploits=exploits,
        validated_exploits=validated_exploits,
        priorities=priorities
    )

@app.route('/download/<domain>')
def download_report(domain):

    if "user" not in session:
        return redirect("/login")

    safe_domain = (
        domain
        .replace("https://", "")
        .replace("http://", "")
        .replace("/", "_")
        .replace(".", "_")
    )
    filename = f"{safe_domain}_report.pdf"

    file_path = os.path.join(os.getcwd(), filename)

    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return f"File not found: {file_path}"

@app.route("/history")
def history():

    if "user" not in session:
        return redirect("/login")

    scans = get_scans()

    return render_template(
        "history.html",
        scans=scans
    )

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        username = request.form["username"]

        password = generate_password_hash(
            request.form["password"]
        )

        success = create_user(username, password)

        if not success:
            return "User already exists"

        return redirect("/login")

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form["username"]

        password = request.form["password"]

        user = authenticate_user(username)

        if user and check_password_hash(user[2], password):

            session["user"] = username

            return redirect("/")

        return "Invalid credentials"

    return render_template("login.html")

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)