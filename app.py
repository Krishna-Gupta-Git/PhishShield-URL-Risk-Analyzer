from flask import Flask, render_template, request
from analyzer import analyze_url
from scorer import calculate_risk

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")
    url = request.form["url"]

@app.route("/analyze", methods=["POST"])
def analyze():
    url = request.form["url"]

    result = analyze_url(url)

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
    return render_template(
    "result.html",
    url=url,
    result=result,
    score=score,
    reasons=reasons,
    risk_level=risk_level,
    recommendation=recommendation
)

if __name__ == "__main__":
    app.run(debug=True)