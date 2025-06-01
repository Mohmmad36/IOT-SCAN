# IoT Vulnerability Scanner

This is a Python-based tool designed to scan a network for connected IoT devices and check them against a vulnerability database. It can also generate a PDF report and update the vulnerability database from an online source.

## Features
- **Network Scanner**: Uses ARP requests to find devices on a specified IP range.
- **Vulnerability Checker**: Compares devices against a local JSON vulnerability database.
- **Database Updater**: Downloads the latest vulnerability database from a given URL.
- **PDF Report Exporter**: Generates a detailed vulnerability report in PDF format.

## Installation
1. Clone this repository:
   ```bash
   git clone https://github.com/yourusername/iot-vuln-scanner.git
   cd iot-vuln-scanner
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage
1. Run the main UI:
   ```bash
   python3 ui.py
   ```
2. Enter the IP range to scan (e.g., `192.168.1.0/24`).
3. Use the GUI buttons to start the scan, update the vulnerability database, or export the PDF report.

## File Structure
- `ui.py`: Main GUI application using Tkinter.
- `scanner.py`: Network scanning and vulnerability checking functions.
- `vuln_db.json`: JSON file containing known vulnerabilities.

## Requirements
- Python 3
- `scapy`
- `fpdf`
- `requests`

## License
This project is licensed under the MIT License.
