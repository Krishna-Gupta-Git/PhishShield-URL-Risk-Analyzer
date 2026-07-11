from flask import Flask, render_template, request
from analyzer import analyze_url

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():

    url = request.form["url"]

    results = analyze_url(url)

    return render_template(
        "result.html",
        url=url,
        results=results
    )


if __name__ == "__main__":
    app.run(debug=True)