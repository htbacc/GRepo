from fpdf import FPDF

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
