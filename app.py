from flask import Flask, render_template, request
from analyzer import analyze_url
from scorer import calculate_risk
from virustotal import submit_url, get_analysis
from whois_lookup import get_domain_info
from ssl_checker import get_ssl_info
from database import (
    initialize_database,
    save_scan,
    get_history
)
from report_generator import generate_report
from flask import send_file

latest_report = {}
app = Flask(__name__)
initialize_database()

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.form["url"]

    result = analyze_url(url)
    domain_info = get_domain_info(url)
    ssl_info = get_ssl_info(url)
    score, reasons = calculate_risk(result)

    if score <= 2:
        risk_level = "Low Risk"
    elif score <= 5:
        risk_level = "Medium Risk"
    else:
        risk_level = "High Risk"

    if risk_level == "Low Risk":
        recommendation = "This website appears safe, but always verify before entering personal information."
    elif risk_level == "Medium Risk":
        recommendation = "Proceed carefully. Verify the website before logging in or sharing sensitive information."
    else:
        recommendation = "Avoid visiting this website. It contains several phishing indicators."

    
    analysis_id = submit_url(url)

    vt_stats = None
    if analysis_id:
        vt_stats = get_analysis(analysis_id)
    
    save_scan(
    url,
    score,
    risk_level
)

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
    global latest_report
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
@app.route("/history")
def history():

    history_data = get_history()

    return render_template(
        "history.html",
        history=history_data
    )
    

@app.route("/download-report")
def download_report():

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