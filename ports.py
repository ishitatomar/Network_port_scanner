import sys
import requests
import socket
import json
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
import argparse
import nmap
import threading

def get_website_info():
    url = url_entry.get()
    result_text.delete(1.0, tk.END)

    try:
        req = requests.get(url)
        gethostby_ = socket.gethostbyname(url.replace("https://", "").replace("http://", ""))
        ip_address = gethostby_
        req_two = requests.get("https://ipinfo.io/" + gethostby_ + "/json")
        resp_ = json.loads(req_two.text)
        location = resp_["loc"]
        region = resp_["region"]
        city = resp_["city"]
        country = resp_["country"]

        result_text.insert(tk.END, f"IP Address: {ip_address}\n\n", "black")
        result_text.insert(tk.END, f"Location: {location}\n", "black")
        result_text.insert(tk.END, f"Region: {region}\n", "black")
        result_text.insert(tk.END, f"City: {city}\n", "black")
        result_text.insert(tk.END, f"Country: {country}\n", "black")

    except requests.exceptions.RequestException as e:
        result_text.insert(tk.END, f"Error: {e}\n", "black")
    except socket.gaierror:
        result_text.insert(tk.END, "Error: Could not resolve hostname.\n", "black")
    except json.JSONDecodeError:
        result_text.insert(tk.END, "Error: Invalid JSON response from ipinfo.io.\n", "black")
    except KeyError:
        result_text.insert(tk.END, "Error: Missing data from ipinfo.io.\n", "black")

def argument_parser(host, ports):
    parser = argparse.ArgumentParser()
    parser.add_argument("-o", "--host", default=host)
    parser.add_argument("-p", "--ports", default=ports)
    var_args = vars(parser.parse_args())
    return var_args

def nmap_scan(host_id, port_num, result_text):
    nm_scan = nmap.PortScanner()
    try:
        nm_scan.scan(host_id, port_num)
        state = nm_scan[host_id]['tcp'][int(port_num)]['state']
        result = ("[*] {host} tcp/{port} {state}\n".format(host=host_id, port=port_num, state=state))
        result_text.insert(tk.END, result, "black")
    except KeyError:
        result = ("[*] {host} tcp/{port} closed or filtered\n".format(host=host_id, port=port_num))
        result_text.insert(tk.END, result, "black")
    except Exception as e:
        result = (f"[*] {host} tcp/{port} scan failed: {e}\n")
        result_text.insert(tk.END, result, "black")

def run_scan():
    host = host_entry.get()
    ports = ports_entry.get()

    if not host or not ports:
        messagebox.showerror("Error", "Please provide a host and port list.")
        return

    try:
        user_args = argument_parser(host, ports)
        host = user_args["host"]
        ports = user_args["ports"].split(",")

        def scan_thread():
            for port in ports:
                nmap_scan(host, port, result_text)

        threading.Thread(target=scan_thread).start()

    except Exception as e:
        messagebox.showerror("Error", f"An unexpected error occurred: {e}")

# GUI Setup
window = tk.Tk()
window.title("Cyber Security Tool")
window.geometry("600x500")
window.configure(bg="#f0f0f0")

# Style Configuration
style = ttk.Style()
style.configure("TButton", padding=5, font=('Arial', 10), background="#4CAF50", foreground="white")
style.configure("TLabel", font=('Arial', 10), background="#f0f0f0")
style.configure("TEntry", padding=5, font=('Arial', 10))

# Website Info Section
website_frame = ttk.LabelFrame(window, text="Website Information", padding=10)
website_frame.pack(pady=10, padx=10, fill=tk.X)

url_label = ttk.Label(website_frame, text="Enter URL:")
url_label.pack(pady=(0, 5))
url_entry = ttk.Entry(website_frame, width=50)
url_entry.pack(pady=(0, 10))
get_info_button = ttk.Button(website_frame, text="Get Website Info", command=get_website_info)
get_info_button.pack()

# Port Scanner Section
port_frame = ttk.LabelFrame(window, text="Port Scanner", padding=10)
port_frame.pack(pady=10, padx=10, fill=tk.X)

host_label = ttk.Label(port_frame, text="Host:")
host_label.pack(pady=(0, 5))
host_entry = ttk.Entry(port_frame, width=50)
host_entry.pack(pady=(0, 10))
ports_label = ttk.Label(port_frame, text="Ports (comma-separated):")
ports_label.pack(pady=(0, 5))
ports_entry = ttk.Entry(port_frame, width=50)
ports_entry.pack(pady=(0, 10))
scan_button = ttk.Button(port_frame, text="Scan Ports", command=run_scan)
scan_button.pack()

# Results Area
result_text = scrolledtext.ScrolledText(window, wrap=tk.WORD, width=60, height=15, bg="#e0e0e0", fg="black") #added fg="black"
result_text.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

#tag for text colour
result_text.tag_configure("black", foreground="black")

window.mainloop()