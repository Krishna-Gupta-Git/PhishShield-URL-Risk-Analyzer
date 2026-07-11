def calculate_risk(result):

    score = 0
    reasons = []

    # HTTPS
    if not result["https"]:
        score += 20
        reasons.append("Website does not use HTTPS.")

    # IP Address
    if result["ip_address"]:
        score += 30
        reasons.append("URL uses an IP address instead of a domain.")

    # Suspicious Words
    if result["suspicious_words"]:
        word_score = len(result["suspicious_words"]) * 10
        score += word_score
        reasons.append(
            "Suspicious words found: " +
            ", ".join(result["suspicious_words"])
        )

    # Hyphen
    if result["hyphen"]:
        score += 10
        reasons.append("Domain contains a hyphen.")

    # Long URL
    if result["length"] > 75:
        score += 10
        reasons.append("URL is unusually long.")

    # Too many subdomains
    if result["subdomains"] > 2:
        score += 10
        reasons.append("Too many subdomains detected.")

    # URL shortener
    if result["shortened"]:
        score += 20
        reasons.append("URL uses a shortening service.")

    # Maximum score = 100
    score = min(score, 100)

    return score, reasons