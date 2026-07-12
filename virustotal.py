import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"


def submit_url(url):
    headers = {
        "x-apikey": API_KEY
    }

    response = requests.post(
        f"{BASE_URL}/urls",
        headers=headers,
        data={"url": url}
    )

    if response.status_code != 200:
        return None

    data = response.json()
    return data["data"]["id"]


def get_analysis(analysis_id):
    headers = {
        "x-apikey": API_KEY
    }

    # Wait for VirusTotal to complete analysis
    time.sleep(3)

    response = requests.get(
        f"{BASE_URL}/analyses/{analysis_id}",
        headers=headers
    )

    if response.status_code != 200:
        return None

    data = response.json()

    stats = data["data"]["attributes"]["stats"]

    return stats