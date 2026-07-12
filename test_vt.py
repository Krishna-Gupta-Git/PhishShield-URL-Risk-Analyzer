from virustotal import submit_url, get_analysis

url = "https://google.com"

analysis_id = submit_url(url)

print("Analysis ID:", analysis_id)

stats = get_analysis(analysis_id)

print(stats)