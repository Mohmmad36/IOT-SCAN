import tkinter as tk
from tkinter import ttk, messagebox
import json
import threading
from scanner import scan_network, check_vulnerabilities, update_vuln_db, export_pdf_report

LOCAL_DB_FILE = 'vuln_db.json'
VULN_DB_URL = "https://raw.githubusercontent.com/Mohmmad36/IOT-SCAN/main/vuln_db.json"

# تحميل قاعدة البيانات عند بدء التشغيل
try:
    with open(LOCAL_DB_FILE, encoding='utf-8') as f:
        vuln_db = json.load(f)
except Exception as e:
    vuln_db = []
    print(f"Failed to load local vulnerability DB: {e}")

def start_scan():
    ip_range = ip_entry.get()
    try:
        devices = scan_network(ip_range)
        results = check_vulnerabilities(devices, vuln_db)
        result_text.delete(1.0, tk.END)
        if not results:
            result_text.insert(tk.END, "✅ No known vulnerabilities found.\n")
        else:
            for r in results:
                result_text.insert(tk.END, f"Device: {r['device_ip']}\n")
                result_text.insert(tk.END, f"MAC: {r['device_mac']}\n")
                result_text.insert(tk.END, f"Manufacturer: {r['manufacturer']}\n")
                result_text.insert(tk.END, f"Device Type: {r['device_type']}\n")
                result_text.insert(tk.END, f"Severity: {r['severity']}\n")
                result_text.insert(tk.END, f"Vulnerability Name: {r['vuln_name']}\n")
                result_text.insert(tk.END, f"Description: {r['description']}\n")
                result_text.insert(tk.END, f"Solution: {r['solution']}\n\n")
    except Exception as e:
        messagebox.showerror("Error", f"An error occurred during scanning: {e}")

def update_database():
    update_button.config(state=tk.DISABLED)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, "🔄 Updating vulnerability database...\n")

    def do_update():
        global vuln_db
        try:
            update_vuln_db(VULN_DB_URL, LOCAL_DB_FILE)
            with open(LOCAL_DB_FILE, encoding='utf-8') as f:
                vuln_db = json.load(f)
            messagebox.showinfo("Success", "✅ Vulnerability database updated successfully.")
            result_text.insert(tk.END, "✅ Update successful.\n")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to update database: {e}")
            result_text.insert(tk.END, f"❌ Update failed: {e}\n")
        finally:
            update_button.config(state=tk.NORMAL)

    threading.Thread(target=do_update).start()

def export_report():
    try:
        devices = scan_network(ip_entry.get())
        results = check_vulnerabilities(devices, vuln_db)
        export_pdf_report(results)
        messagebox.showinfo("Success", "✅ PDF report created successfully.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to create report: {e}")

root = tk.Tk()
root.title("IoT Vulnerability Scanner")
root.geometry("650x550")

frame = ttk.Frame(root, padding="10")
frame.pack(fill="both", expand=True)

ip_label = ttk.Label(frame, text="Enter IP Range:")
ip_label.pack(anchor="w")

ip_entry = ttk.Entry(frame, width=50)
ip_entry.insert(0, "192.168.1.0/24")
ip_entry.pack(anchor="w", pady=5)

scan_button = ttk.Button(frame, text="Start Scan", command=start_scan)
scan_button.pack(anchor="w", pady=5)

url_label = ttk.Label(frame, text="Vulnerability DB URL:")
url_label.pack(anchor="w", pady=5)

url_entry = ttk.Entry(frame, width=50)
url_entry.insert(0, VULN_DB_URL)
url_entry.pack(anchor="w", pady=5)

update_button = ttk.Button(frame, text="Update Database", command=update_database)
update_button.pack(anchor="w", pady=5)

export_button = ttk.Button(frame, text="Export PDF Report", command=export_report)
export_button.pack(anchor="w", pady=5)

result_text = tk.Text(frame, wrap="word")
result_text.pack(fill="both", expand=True, pady=10)

root.mainloop()

