import scapy.all as scapy
import json
import requests
from fpdf import FPDF

def scan_network(ip_range):
    devices = []
    arp_request = scapy.ARP(pdst=ip_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = scapy.srp(arp_request_broadcast, timeout=2, verbose=False)[0]
    for element in answered:
        devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
    return devices

def check_vulnerabilities(devices, vuln_db):
    results = []
    for device in devices:
        for vuln in vuln_db:
            if device['mac'].lower().startswith(vuln['mac_prefix'].lower()):
                results.append({
                    "device_ip": device['ip'],
                    "device_mac": device['mac'],
                    "manufacturer": vuln.get('manufacturer', 'Unknown'),
                    "device_type": vuln.get('device_type', 'Unspecified'),
                    "vuln_name": vuln['name'],
                    "severity": vuln.get('severity', 'Unspecified'),
                    "description": vuln.get('description', 'No description available'),
                    "solution": vuln['solution']
                })
    return results

def update_vuln_db(url, local_file):
    try:
        response = requests.get(url)
        response.raise_for_status()
        with open(local_file, 'w', encoding='utf-8') as f:
            f.write(response.text)
        print("✅ Vulnerability database updated successfully.")
    except Exception as e:
        print(f"❌ Update failed: {e}")

def export_pdf_report(results, filename="vuln_report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="IoT Devices Vulnerability Report", ln=True, align='C')
    pdf.ln(10)
    if not results:
        pdf.cell(200, 10, txt="No known vulnerabilities found.", ln=True, align='L')
    else:
        for r in results:
            pdf.multi_cell(0, 10, txt=(
                f"IP: {r['device_ip']}\n"
                f"MAC: {r['device_mac']}\n"
                f"Manufacturer: {r['manufacturer']}\n"
                f"Device Type: {r['device_type']}\n"
                f"Severity: {r['severity']}\n"
                f"Vulnerability Name: {r['vuln_name']}\n"
                f"Description: {r['description']}\n"
                f"Solution: {r['solution']}\n"
            ), align='L')
            pdf.ln(5)
    pdf.output(filename)
    print(f"✅ Report generated: {filename}")
