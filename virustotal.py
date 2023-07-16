# pip install virustotal-python
# pip install --upgrade urllib3 requests

import tkinter as tk
from tkinter import messagebox
import virustotal_python
from base64 import urlsafe_b64encode
import hashlib

def calculate_sha256(url):
    sha256_hash = hashlib.sha256(url.encode()).hexdigest()
    return sha256_hash

def upload_file():
    vtotal_api_key = "VIRUS_TOTAL_API_KEY"
    v_url = file_entry.get()

    # Calculate SHA-256 hash of the URL
    url_hash = calculate_sha256(v_url)

    with virustotal_python.Virustotal(vtotal_api_key) as vtotal:
        try:
            resp = vtotal.request("urls", data={"url": v_url}, method="POST")
            # Safe encode URL in base64 format
            # https://developers.virustotal.com/reference/url
            url_id = urlsafe_b64encode(v_url.encode()).decode().strip("=")
            report = vtotal.request(f"urls/{url_id}")
            v_result_url = report.data['attributes']['last_analysis_stats']
            result_text.config(state="normal")
            result_text.delete("1.0", tk.END)
            result_text.insert(tk.END, f"URL: {v_url}\n")
            result_text.insert(tk.END, f"SHA-256 Hash: {url_hash}\n")
            result_text.insert(tk.END, f"Analysis Result:\n{v_result_url}\n")
            result_text.config(state="disabled")
        except virustotal_python.VirustotalError as err:
            messagebox.showerror("Error", f"Failed to send URL for analysis and get the report: {err}")

# Create the main window
window = tk.Tk()
window.title("VirusTotal Web Analysis")
window.geometry("400x300")

# Create the file entry field
file_entry = tk.Entry(window, width=40)
file_entry.pack(pady=10)

# Create the upload button
upload_button = tk.Button(window, text="Upload", command=upload_file)
upload_button.pack(pady=10)

# Create the text widget to display the result
result_text = tk.Text(window, width=40, height=10)
result_text.config(state="disabled")
result_text.pack(pady=10)

# Start the GUI event loop
window.mainloop()
