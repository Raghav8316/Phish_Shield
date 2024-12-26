import tkinter as tk #for GUI 
from tkinter import ttk , messagebox 
import re #tool for identifying patterns
import webbrowser #opens web pages by clicking
import requests #for API requests sending

#Initialize Global Variables
url_history = [] #stores url history
VT_API_KEY=""

#Validate URL
def is_valid_url(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False
    
#Analyze URL Function
def analyze_url():
    url= url_entry.get().strip() #Retrieves the entered URL from the input box and removes extra spaces
    if not url:
        feedback_label.config(text= "Please enter a valid URL.",fg="red")
        percentage_meter['value']= 0
        percentage_label.config(text="Suspicious Probability: 0.00%")
        return
    
    # Automatically add "https://" if not present
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url
        url_entry.delete(0, tk.END)
        url_entry.insert(0, url)

    # Validate URL
    if not is_valid_url(url):
        feedback_label.config(text="The URL does not exist. Please check again.", fg="red")
        return

    feedback_label.config(text="Scanning...", fg="blue")
    root.update_idletasks()

    # Predefined list of malicious keywords
    malicious_keywords = ["free", "click", "login", "verify", "update", "secure", "account", "offer"]

    # Initialize suspicious score
    suspicious_count = 0

    # Check for malicious keywords
    for keyword in malicious_keywords:
        if re.search(keyword, url, re.IGNORECASE):
            suspicious_count += 1

    # Check URL length
    if len(url) > 75:
        suspicious_count += 1

    # Check for special characters
    if re.search(r"[%@&]", url):
        suspicious_count += 1

    # Check for HTTPS
    if not url.startswith("https://"):
        suspicious_count += 1

    # Check with VirusTotal API
    try:
        headers = {"x-apikey": VT_API_KEY}
        data = {"url": url}
        vt_response = requests.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=data)

        if vt_response.status_code == 200:
            analysis_id = vt_response.json()["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            analysis_response = requests.get(analysis_url, headers=headers)

            if analysis_response.status_code == 200:
                results = analysis_response.json()["data"]["attributes"]["stats"]
                malicious_count = results.get("malicious", 0)
                if malicious_count > 0:
                    suspicious_count += 1
        else:
            feedback_label.config(text="VirusTotal check failed. Try again later.", fg="orange")
    except Exception:
        feedback_label.config(text="Error connecting to VirusTotal.", fg="orange")

    
     # Calculate percentage possibility
    total_checks = len(malicious_keywords) + 4  # Keywords, length, special characters, HTTPS, VirusTotal
    percentage = (suspicious_count / total_checks) * 100

    # Determine classification
    if percentage == 0:
        feedback_label.config(text="The URL is Secure.", fg="green")
        go_button.config(bg="SystemButtonFace")  # Reset button color
    else:
        feedback_label.config(text="The URL is Suspicious!", fg="red")
        go_button.config(bg="red")  # Change button color to red

     # Update the progress bar
    percentage_meter['value'] = percentage
    percentage_label.config(text=f"Suspicious Probability: {percentage:.2f}%")

    # Add URL to history if not already present
    if url not in url_history:
        url_history.append(url)
        url_dropdown['values'] = url_history

def clear_input():
    url_entry.delete(0, tk.END)
    feedback_label.config(text="")
    percentage_meter['value'] = 0
    percentage_label.config(text="Suspicious Probability: 0.00%")

def open_website():
    url = url_entry.get().strip()
    if url:
        if not url.startswith("http://") and not url.startswith("https://"):
            url = "https://" + url
        webbrowser.open(url)
    else:
        messagebox.showerror("Error", "Please enter a valid URL to visit.")

def select_url(event):
    selected_url = url_dropdown.get()
    url_entry.delete(0, tk.END)
    url_entry.insert(0, selected_url)

def clear_history():
    url_history.clear()
    url_dropdown['values'] = url_history
    feedback_label.config(text="History cleared.", fg="green")

# GUI setup
root = tk.Tk()
root.title("PhishShield")
root.geometry("500x550")

# URL input label and entry box
url_label = tk.Label(root, text="Enter URL:")
url_label.pack(pady=5)
url_entry = tk.Entry(root, width=50)
url_entry.pack(pady=5)

# Analyze button
analyze_button = tk.Button(root, text="Analyze URL", command=analyze_url)
analyze_button.pack(pady=5)

# Clear button
clear_button = tk.Button(root, text="Clear", command=clear_input)
clear_button.pack(pady=10)

# Go to website button
go_button = tk.Button(root, text="Go to Website", command=open_website)
go_button.pack(pady=5)

# Feedback label
feedback_label = tk.Label(root, text="", font=("Arial", 12))
feedback_label.pack(pady=10)

# Percentage meter
percentage_meter = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
percentage_meter.pack(pady=5)

# Percentage label
percentage_label = tk.Label(root, text="Suspicious Probability: 0.00%")
percentage_label.pack(pady=5)

# History section
history_label = tk.Label(root, text="History:", font=("Arial", 10, "bold"))
history_label.pack(pady=10)
url_dropdown = ttk.Combobox(root, state="readonly", values=url_history, width=60)
url_dropdown.pack(pady=5)
url_dropdown.bind("<<ComboboxSelected>>", select_url)

# Clear history button
clear_history_button = tk.Button(root, text="Clear History", command=clear_history)
clear_history_button.pack(pady=5)

root.mainloop()

    
    
    

