from flask import Flask, render_template_string, send_file, request
import requests
from bs4 import BeautifulSoup
from io import BytesIO
from openpyxl import Workbook
from PIL import Image, ImageDraw, ImageFont

app = Flask(__name__)

SAP_URL = "https://support.sap.com/en/my-support/knowledge-base/security-notes-news/february-2026.html"

# Emoji mapping for severity
EMOJI_MAP = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢"
}

def get_emoji(priority):
    return EMOJI_MAP.get(priority.lower(), "")

def fetch_sap_data():
    headers = {"User-Agent": "Mozilla/5.0"}
    resp = requests.get(SAP_URL, headers=headers)
    resp.raise_for_status()

    soup = BeautifulSoup(resp.text, "html.parser")
    all_rows = []

    tables = soup.find_all("table")

    for table in tables:
        for tr in table.find_all("tr")[1:]:
            cols = tr.find_all("td")
            if len(cols) < 4:
                continue

            # CVE ID
            cve_links = cols[1].find_all("a")
            cve_ids = [a.text.strip() for a in cve_links if "CVE" in a.text]
            cve_id = ", ".join(cve_ids) if cve_ids else "N/A"

            # Priority / Criticality
            priority = cols[2].get_text(strip=True)

            # CVSS score
            cvss_link = cols[3].find("a")
            cvss = cvss_link.text.strip() if cvss_link else cols[3].text.strip()

            # Title — remove repeated version text and empty brackets
            raw_title = cols[1].get_text(" ", strip=True)
            title = raw_title
            if "Version(s) -" in raw_title:
                title = raw_title.split("Version(s) -")[0].strip()
            title = title.replace("[  ]", "").strip()

            # Extract versions
            versions = ""
            for p in cols[1].find_all("p"):
                text = p.get_text(" ", strip=True)
                if "Version(s) -" in text:
                    versions = text.replace("Version(s) -", "").strip()
                    break

            all_rows.append({
                "CVE ID": cve_id,
                "Criticality": priority,
                "CVSS": cvss,
                "Title": title,
                "Versions": versions
            })

    return all_rows

def build_ascii_table(rows):
    col1_w = 16

    # find longest content for col2
    max_len = 0
    for r in rows:
        for key in ["CVE ID", "Criticality", "CVSS", "Title", "Versions"]:
            max_len = max(max_len, len(r[key]) + (2 if key == "Criticality" else 0))
    col2_w = max(max_len, 80)

    sep = "+" + "-"*col1_w + "+" + "-"*col2_w + "+"

    lines = [sep]
    for r in rows:
        em = get_emoji(r["Criticality"])
        lines.append(f"| CVE ID         | {r['CVE ID']:<{col2_w}}")
        lines.append(f"| Criticality    | {r['Criticality']} {em:<{col2_w - len(r['Criticality']) - 1}}")
        lines.append(f"| CVSS           | {r['CVSS']:<{col2_w}}")
        lines.append(f"| Title          | {r['Title']:<{col2_w}}")
        lines.append(f"| Versions       | {r['Versions']:<{col2_w}}")
        lines.append(sep)

    return "\n".join(lines)

def generate_excel(rows):
    wb = Workbook()
    ws = wb.active
    ws.title = "SAP Security Notes"

    headers = ["CVE ID", "Criticality", "CVSS", "Title", "Versions"]
    ws.append(headers)

    for r in rows:
        ws.append([r[h] for h in headers])

    bio = BytesIO()
    wb.save(bio)
    bio.seek(0)
    return bio

def generate_image(rows):
    table_text = build_ascii_table(rows)
    font = ImageFont.load_default()
    lines = table_text.splitlines()
    max_width = max([font.getlength(line) for line in lines])
    line_height = font.getbbox("Hg")[3] - font.getbbox("Hg")[1] + 2

    img = Image.new("RGB", (int(max_width)+20, line_height*len(lines)+20), color=(30,30,30))
    draw = ImageDraw.Draw(img)
    y = 10
    for line in lines:
        draw.text((10, y), line, font=font, fill=(212,212,212))
        y += line_height

    bio = BytesIO()
    img.save(bio, format="PNG")
    bio.seek(0)
    return bio

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SAP Security Notes ASCII Table</title>
<style>
    body { font-family: monospace; background: #1e1e1e; color: #d4d4d4; padding: 20px; }
    #terminal { background: #1e1e1e; padding: 15px; border: 1px solid #444; border-radius: 5px; white-space: pre; overflow-x: auto; }
    button {
        margin-top: 15px;
        padding: 8px 14px;
        font-size: 15px;
        cursor: pointer;
        border: none;
        border-radius: 4px;
        background: #007acc;
        color: white;
    }
    button:hover { background: #005c99; }
</style>
</head>
<body>
    <h2>SAP Security Patch Day - January 2026</h2>

    <button onclick="copyTable()">Copy Table</button>
    <a href="/download/excel"><button>Download Excel</button></a>
    <a href="/download/image"><button>Download Image</button></a>

    <div id="terminal">{{ table }}</div>

    <script>
    function copyTable() {
        const txt = document.getElementById("terminal").innerText;
        navigator.clipboard.writeText(txt).then(() => {
            alert("Table copied to clipboard!");
        });
    }
    </script>
</body>
</html>
"""

@app.route("/")
def index():
    rows = fetch_sap_data()
    ascii_tbl = build_ascii_table(rows)
    return render_template_string(HTML_TEMPLATE, table=ascii_tbl)

@app.route("/download/excel")
def download_excel():
    rows = fetch_sap_data()
    bio = generate_excel(rows)
    return send_file(
        bio,
        download_name="sap_security_notes.xlsx",
        as_attachment=True,
        mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

@app.route("/download/image")
def download_image():
    rows = fetch_sap_data()
    bio = generate_image(rows)
    return send_file(
        bio,
        download_name="sap_security_notes.png",
        as_attachment=True,
        mimetype="image/png"
    )

if __name__ == "__main__":
    app.run(debug=True)
