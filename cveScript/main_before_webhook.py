import pandas as pd
from pdf_generation import PDF
from database import create_connection, create_table, add_missing_columns, insert_data
from scraper import scrape_data

# List of items to be queried
query_items = ["sap", "hana", "netweaver","successfactors","apache","httpd","nginx","java","linux","exim","smtpd","node","squid","react","http","ftp","tcp","icmp","rdp","ssh","telnet","smtp","dns","tftp","dhcp","tls","arp","bgp","smb","igmp","rpc","onedrive","teams","edge","word","excel","skype","office","powershell","powerpoint","chrome","7zip","moveit","adobe","jdk","jre","guacamole","splunk","suricata","checkmk"]
# Base URL
base_url = "https://nvd.nist.gov/vuln/search/results?form_type=Basic&results_type=overview&search_type=all&isCpeNameSearch=false&query="

# Connect to SQLite database (or create it if it doesn't exist)
conn = create_connection('vulnerability_data.db')
create_table(conn)
add_missing_columns(conn)

# Create a PDF document in landscape orientation
pdf = PDF('L', 'mm', 'A4')
pdf.add_page()

# Iterate over each item in the list
for item in query_items:
    cve_ids, published_dates, cvss_v3_scores, cvss_v2_scores = scrape_data(base_url, item)
    
    for cve_id, published_date, cvss_v3_score, cvss_v2_score in zip(cve_ids, published_dates, cvss_v3_scores, cvss_v2_scores):
        insert_data(conn, cve_id, published_date, cvss_v3_score, cvss_v2_score, item)

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
cursor = conn.cursor()

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

