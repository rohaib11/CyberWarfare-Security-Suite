from fpdf import FPDF
import datetime
import os

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 15)
        self.cell(0, 10, 'PC Security Monitor - Audit Report', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_security_report(logs):
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    
    # Title Info
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(200, 10, txt=f"Generated on: {timestamp}", ln=True, align='L')
    pdf.cell(200, 10, txt=f"Total Events: {len(logs)}", ln=True, align='L')
    pdf.ln(10)
    
    # Table Header
    pdf.set_fill_color(200, 220, 255)
    pdf.cell(190, 10, txt="Security Event Logs", border=1, ln=True, align='C', fill=True)
    
    # Log Entries
    pdf.set_font("Courier", size=10)
    for log in logs:
        # Clean text to avoid unicode errors in simple PDF
        clean_log = str(log).encode('latin-1', 'replace').decode('latin-1')
        pdf.multi_cell(0, 10, txt=f"- {clean_log}", border=0)
        pdf.ln(2)
        
    # Save
    filename = f"Security_Report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(filename)
    
    return os.path.abspath(filename)