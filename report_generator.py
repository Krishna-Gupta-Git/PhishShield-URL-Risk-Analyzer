from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)
from reportlab.lib.styles import getSampleStyleSheet
from datetime import datetime


def generate_report(
    filename,
    url,
    score,
    risk_level,
    recommendation,
    result,
    vt_stats,
    domain_info,
    ssl_info
):

    styles = getSampleStyleSheet()

    doc = SimpleDocTemplate(filename)

    story = []

    story.append(Paragraph("<b>PHISHSHIELD SECURITY REPORT</b>", styles["Title"]))
    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            f"<b>Scan Time:</b> {datetime.now()}",
            styles["Normal"]
        )
    )

    story.append(
        Paragraph(
            f"<b>URL:</b> {url}",
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 15))

    story.append(
        Paragraph(
            f"<b>Risk Score:</b> {score}%",
            styles["Normal"]
        )
    )

    story.append(
        Paragraph(
            f"<b>Risk Level:</b> {risk_level}",
            styles["Normal"]
        )
    )

    story.append(Spacer(1, 15))

    story.append(Paragraph("<b>URL Analysis</b>", styles["Heading2"]))

    for key, value in result.items():
        story.append(
            Paragraph(
                f"{key}: {value}",
                styles["Normal"]
            )
        )

    story.append(Spacer(1, 15))

    story.append(
        Paragraph("<b>VirusTotal</b>", styles["Heading2"])
    )

    if vt_stats:

        for key, value in vt_stats.items():

            story.append(
                Paragraph(
                    f"{key}: {value}",
                    styles["Normal"]
                )
            )

    else:

        story.append(
            Paragraph(
                "VirusTotal unavailable",
                styles["Normal"]
            )
        )

    story.append(Spacer(1, 15))

    story.append(
        Paragraph("<b>WHOIS</b>", styles["Heading2"])
    )

    if domain_info:

        for key, value in domain_info.items():

            story.append(
                Paragraph(
                    f"{key}: {value}",
                    styles["Normal"]
                )
            )

    story.append(Spacer(1, 15))

    story.append(
        Paragraph("<b>SSL Certificate</b>", styles["Heading2"])
    )

    if ssl_info:

        for key, value in ssl_info.items():

            story.append(
                Paragraph(
                    f"{key}: {value}",
                    styles["Normal"]
                )
            )

    story.append(Spacer(1, 20))

    story.append(
        Paragraph(
            f"<b>Recommendation:</b> {recommendation}",
            styles["Normal"]
        )
    )

    doc.build(story)