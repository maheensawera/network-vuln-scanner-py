import json
from fpdf import FPDF, XPos, YPos
from datetime import datetime

class VulnerabilityReport(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 16)
        self.cell(0, 10, 'Network Vulnerability Assessment Report', 0,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        self.set_font('Helvetica', '', 10)
        self.cell(0, 8, f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}', 0,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, align='C')


def generate_report(json_file, output_file):
    with open(json_file, 'r') as f:
        data = json.load(f)

    pdf = VulnerabilityReport()
    pdf.add_page()

    pdf.set_font('Helvetica', 'B', 12)
    pdf.set_x(pdf.l_margin)
    pdf.cell(0, 10, 'Executive Summary', 0, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.set_font('Helvetica', '', 10)

    total_ports = 0
    total_cves = 0
    for host in data['hosts']:
        total_ports += len(host['open_ports'])
        for port in host['open_ports']:
            total_cves += len(port['cves'])

    summary = (f"Target scanned: {data['target']}\n"
               f"Scan time: {data['scan_time']}\n"
               f"Total open ports found: {total_ports}\n"
               f"Total known vulnerabilities (CVEs) identified: {total_cves}")
    pdf.set_x(pdf.l_margin)
    pdf.multi_cell(0, 7, summary)
    pdf.ln(5)

    for host in data['hosts']:
        pdf.set_font('Helvetica', 'B', 12)
        pdf.set_x(pdf.l_margin)
        pdf.cell(0, 10, f"Findings for Host: {host['ip']} ({host['state']})", 0,
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(2)

        for port_info in host['open_ports']:
            has_cve = len(port_info['cves']) > 0
            risk = "HIGH RISK" if has_cve else "Informational"

            pdf.set_font('Helvetica', 'B', 10)
            pdf.set_text_color(200, 0, 0) if has_cve else pdf.set_text_color(0, 0, 0)
            pdf.set_x(pdf.l_margin)
            pdf.cell(0, 7, f"Port {port_info['port']}/{port_info['protocol']} - "
                           f"{port_info['service']} [{risk}]", 0,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.set_font('Helvetica', '', 9)
            pdf.set_text_color(0, 0, 0)
            pdf.set_x(pdf.l_margin)
            details = f"Product: {port_info['product']} {port_info['version']}"
            pdf.cell(0, 6, details, 0, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            if has_cve:
                cve_list = ", ".join(port_info['cves'])
                pdf.set_text_color(200, 0, 0)
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(0, 6, f"Known Vulnerabilities: {cve_list}")

                pdf.set_text_color(0, 0, 0)
                pdf.set_font('Helvetica', 'I', 9)
                pdf.set_x(pdf.l_margin)
                pdf.multi_cell(0, 6, "Recommendation: Update to the latest stable version "
                                     "immediately and review vendor security advisories.")

            pdf.ln(3)

    pdf.output(output_file)
    print(f"[+] Report saved as {output_file}")


if __name__ == "__main__":
    generate_report("scan_results.json", "vulnerability_report.pdf")
