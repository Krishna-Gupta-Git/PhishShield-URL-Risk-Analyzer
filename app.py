from flask import Flask, render_template, request, send_file

from analyzer import analyze_url
from scorer import calculate_risk
from virustotal import submit_url, get_analysis
from whois_lookup import get_domain_info
from ssl_checker import get_ssl_info
from report_generator import generate_report

from database import (
    initialize_database,
    save_scan,
    get_history,
    get_dashboard_stats,
    get_recent_scans
)
app = Flask(__name__)

initialize_database()

# Stores the latest scan for PDF generation
latest_report = {}


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    global latest_report

    url = request.form["url"]

    # URL Analysis
    result = analyze_url(url)

    # WHOIS
    domain_info = get_domain_info(url)

    # SSL
    ssl_info = get_ssl_info(url)

    # Risk Score
    score, reasons = calculate_risk(result)

    # Risk Level
    if score <= 2:
        risk_level = "Low Risk"
    elif score <= 5:
        risk_level = "Medium Risk"
    else:
        risk_level = "High Risk"

    # Recommendation
    if risk_level == "Low Risk":
        recommendation = (
            "This website appears safe, but always verify before entering personal information."
        )

    elif risk_level == "Medium Risk":
        recommendation = (
            "Proceed carefully. Verify the website before logging in or sharing sensitive information."
        )

    else:
        recommendation = (
            "Avoid visiting this website. It contains several phishing indicators."
        )

    # VirusTotal
    analysis_id = submit_url(url)

    vt_stats = None

    if analysis_id:
        vt_stats = get_analysis(analysis_id)

    # Save scan in database
    save_scan(
        url,
        score,
        risk_level
    )

    # Store latest report for PDF generation
    latest_report = {
        "url": url,
        "score": score,
        "risk_level": risk_level,
        "recommendation": recommendation,
        "result": result,
        "vt_stats": vt_stats,
        "domain_info": domain_info,
        "ssl_info": ssl_info
    }

    return render_template(
        "result.html",
        url=url,
        result=result,
        score=score,
        reasons=reasons,
        risk_level=risk_level,
        recommendation=recommendation,
        vt_stats=vt_stats,
        domain_info=domain_info,
        ssl_info=ssl_info
    )


@app.route("/history")
def history():

    history_data = get_history()

    return render_template(
        "history.html",
        history=history_data
    )

@app.route("/dashboard")
def dashboard():

    stats = get_dashboard_stats()

    recent = get_recent_scans()

    return render_template(
        "dashboard.html",
        stats=stats,
        recent=recent
    )

@app.route("/download-report")
def download_report():

    global latest_report

    if not latest_report:
        return "Please analyze a URL first before downloading the report."

    filename = "PhishShield_Report.pdf"

    generate_report(
        filename,
        latest_report["url"],
        latest_report["score"],
        latest_report["risk_level"],
        latest_report["recommendation"],
        latest_report["result"],
        latest_report["vt_stats"],
        latest_report["domain_info"],
        latest_report["ssl_info"]
    )

    return send_file(
        filename,
        as_attachment=True
    )


if __name__ == "__main__":
    app.run(debug=True)