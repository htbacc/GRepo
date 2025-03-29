import sqlite3
import requests
from bs4 import BeautifulSoup
import pandas as pd
from fpdf import FPDF
from datetime import datetime, timedelta

# List of items to be queried
query_items = ["sap", "hana", "netweaver", "successfactors", "apache", "httpd", "nginx", "java", "linux", "exim", "smtpd", "node", "squid", "react", "http", "ftp", "tcp", "icmp", "rdp", "ssh", "telnet", "smtp", "dns", "tftp", "dhcp", "tls", "arp", "bgp", "smb", "igmp", "rpc", "onedrive", "teams", "edge", "word", "excel", "skype", "office", "powershell", "powerpoint", "chrome", "7zip", "moveit", "adobe", "jdk", "jre", "guacamole", "splunk", "suricata", "checkmk"]  # Replace with your list of items

# Base URL
base_url = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query="

# Create a class for PDF generation with UTF-8 encoding
class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, 'CVE Monitoring', 0, 1, 'C')

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.cell(0, 10, title.encode('latin-1', 'replace').decode('latin-1'), 0, 1, 'L')
        self.ln(10)

    def chapter_body(self, body):
        self.set_font('Arial', '', 12)
        self.multi_cell(0, 10, body.encode('latin-1', 'replace').decode('latin-1'))
        self.ln()

    def table(self, header, data):
        col_widths = [40, 80, 40, 40]  # Adjusted column widths
        self.set_font('Arial', 'B', 12)
        for i, col in enumerate(header):
            self.cell(col_widths[i], 10, col, 1)
        self.ln()
        self.set_font('Arial', '', 12)
        for row in data:
            for i, item in enumerate(row):
                if i == 0:  # CVE ID column
                    cve_id = item
                    link = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    self.cell(col_widths[i], 10, f'{cve_id}', 1, link=link)
                elif i >= 2 and item != "N/A":  # CVSS score columns
                    score_text = item.split()[0]  # Get the numeric part of the score
                    score = float(score_text)
                    if score <= 6:
                        self.set_fill_color(0, 0, 255)  # Blue
                    elif 6 < score <= 7:
                        self.set_fill_color(255, 255, 0)  # Yellow
                    elif 7.5 <= score < 9:
                        self.set_fill_color(255, 165, 0)  # Orange
                    elif score >= 9:
                        self.set_fill_color(255, 0, 0)  # Red
                    self.cell(col_widths[i], 10, item.encode('latin-1', 'replace').decode('latin-1'), 1, fill=True)
                else:
                    self.cell(col_widths[i], 10, item.encode('latin-1', 'replace').decode('latin-1'), 1)
            self.ln()

# Connect to SQLite database (or create it if it doesn't exist)
conn = sqlite3.connect('vulnerability_data.db')
cursor = conn.cursor()

# Create a table for storing CVE data
cursor.execute('''
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        cve_id TEXT PRIMARY KEY,
        published_date TEXT,
        cvss_v3_score TEXT,
        cvss_v2_score TEXT,
        query_item TEXT,
        scan_date DATE
    )
''')
conn.commit()

# Create a PDF document in landscape orientation
pdf = PDF('L', 'mm', 'A4')
pdf.add_page()

# Iterate over each item in the list
for item in query_items:
    url = base_url + item
    response = requests.get(url)
    response.raise_for_status()
    soup = BeautifulSoup(response.content, 'html.parser')
    rows = soup.find_all('tr', {'data-testid': lambda x: x and x.startswith('vuln-row-')})
    
    cve_ids = []
    published_dates = []
    cvss_v3_scores = []
    cvss_v2_scores = []

    for row in rows:
        cve_id = row.find('a', {'data-testid': lambda x: x and x.startswith('vuln-detail-link-')}).text.strip()
        published_date = row.find('span', {'data-testid': lambda x: x and x.startswith('vuln-published-on-')}).text.strip()
        
        cvss_v3 = row.find('a', {'data-testid': lambda x: x and x.startswith('vuln-cvss3-link-')})
        cvss_v3_score = cvss_v3.text.strip() if cvss_v3 else "N/A"
        
        cvss_v2 = row.find('a', {'data-testid': lambda x: x and x.startswith('vuln-cvss2-link-')})
        cvss_v2_score = cvss_v2.text.strip() if cvss_v2 else "N/A"
        
        cve_ids.append(cve_id)
        published_dates.append(published_date)
        cvss_v3_scores.append(cvss_v3_score)
        cvss_v2_scores.append(cvss_v2_score)
        
        # Insert data into the database with the current date
        cursor.execute('''
            INSERT OR IGNORE INTO vulnerabilities (cve_id, published_date, cvss_v3_score, cvss_v2_score, query_item, scan_date)
            VALUES (?, ?, ?, ?, ?, DATE('now'))
        ''', (cve_id, published_date, cvss_v3_score, cvss_v2_score, item))

    conn.commit()

    df = pd.DataFrame({
        'CVE ID': cve_ids,
        'Published Date': published_dates,
        'CVSS v3 Score': cvss_v3_scores,
        'CVSS v2 Score': cvss_v2_scores
    })
    
    pdf.add_page()
    pdf.chapter_title(f'Results for query: {item}')
    
    header = list(df.columns)
    data = df.values.tolist()
    pdf.table(header, data)

# Fetch new alerts by comparing with the previous day's data
cursor.execute('''
    SELECT cve_id, published_date, cvss_v3_score, cvss_v2_score, query_item
    FROM vulnerabilities
    WHERE scan_date = DATE('now', '-1 day')
''')
yesterday_data = cursor.fetchall()

cursor.execute('''
    SELECT cve_id, published_date, cvss_v3_score, cvss_v2_score, query_item
    FROM vulnerabilities
    WHERE scan_date = DATE('now')
''')
today_data = cursor.fetchall()

# Convert data to DataFrame for comparison
df_yesterday = pd.DataFrame(yesterday_data, columns=['CVE ID', 'Published Date', 'CVSS v3 Score', 'CVSS v2 Score', 'Query Item'])
df_today = pd.DataFrame(today_data, columns=['CVE ID', 'Published Date', 'CVSS v3 Score', 'CVSS v2 Score', 'Query Item'])

# Merge the DataFrames to find new alerts
new_alerts_df = df_today[~df_today['CVE ID'].isin(df_yesterday['CVE ID'])]

# Create a new PDF page for new alerts
pdf.add_page()
pdf.chapter_title('New Alerts')

if not new_alerts_df.empty:
    new_data = new_alerts_df.values.tolist()
    pdf.table(list(new_alerts_df.columns), new_data)
else:
    pdf.chapter_body("No new alerts found.")

# Save the PDF
pdf.output('new_vulnerability_report.pdf')

print('PDF generated successfully: new_vulnerability_report.pdf')
conn.close()
