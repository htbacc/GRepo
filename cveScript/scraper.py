import requests
from bs4 import BeautifulSoup

def scrape_data(base_url, query_item):
    url = base_url + query_item
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

    return cve_ids, published_dates, cvss_v3_scores, cvss_v2_scores
