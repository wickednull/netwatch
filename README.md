# NetWatch Toolkit v2.3

**Author:** wickedNull
**License:** For educational and authorized use only  
**Platform:** Linux (requires root)

---

## 🔥 What is NetWatch?

**NetWatch Toolkit** is a powerful, modular, and extensible offensive security suite with a cyberpunk-themed GUI. It is built in Python and designed for penetration testers, red teamers, and cybersecurity students. It combines reconnaissance, exploitation, spoofing, and monitoring tools into one cohesive interface.

---

## 🚀 Features

### 🧠 Reconnaissance
- **Nmap Scanner** – Stealth & Pingless scans
- **WHOIS Lookup** – Domain/IP ownership details
- **GeoIP Location** – Approximate IP geolocation
- **ASN Info** – BGP ASN and hosting provider detection
- **Traceroute** – Visualize route to target

### 📡 Network Tools
- **ARP Scan** – Discover devices on the LAN
- **ARP Spoofing** – Intercept target ↔ gateway traffic
- **ARP Kick** – Kick devices off LAN by poisoning ARP cache
- **Deauth Attack** – Disconnect wireless clients using 802.11 packets *(monitor mode required)*
- **DNS Spoofing** – Redirect domains to malicious IPs

### 🛠 Exploitation
- **Metasploit Launcher** – Launch Metasploit modules with GUI configs
- **CVE Scanner** – Parse Nmap results and identify usable CVEs
- **SearchSploit Integration** – Cross-reference local exploits with CVEs

### 🎭 Social Engineering
- **Evil Captive Portal** – Launch fake AP with credential capture
- **HTML Import** – Use your own phishing templates
- **Credential Viewer** – View captured logins from captive portal

### 💻 Remote Access
- **Reverse Shell Listener** – One-click netcat listener
- **Port Capture** – Start live packet sniffing (with monitor mode)
- **Bandwidth Monitor** – Launch `iftop` for live bandwidth analysis

### 🔐 Identity & Control
- **MAC Address Changer** – Spoof MACs randomly or manually
- **Firewall Rule Manager** – Apply iptables rules from GUI

### 📁 Logging & Session Management
- **Session Export** – Save logs from all tools into a file
- **Session Manager** – Save/load current GUI input states
- **Reset Toolkit** – Clears all GUI input fields instantly

---

## 💻 Requirements

- Python 3.x
- `scapy`, `tkinter`, `nmap`
- Tools: `hostapd`, `dnsmasq`, `netcat`, `tcpdump`, `iftop`, `whois`, `geoip-bin`, `metasploit-framework`, `searchsploit`

Install missing tools via:

```bash
sudo apt install nmap netcat dnsmasq hostapd tcpdump iftop whois geoip-bin metasploit-framework exploitdb
pip3 install scapy

⸻

🧪 Usage

sudo python3 netwatchV2.py

or for recent release.

sudo python3 netwatchDev.py

⸻

📂 Evil Portal Directory

Captured credentials and portal HTML are stored in:

netwatch_portal/

⚠️ Disclaimer

This toolkit is for educational and authorized use only. Unauthorized access or misuse of network tools may be illegal. Always have permission before scanning or attacking any network or device.

⸻

🌐 Contact

Author: Niko DeRuise
GitHub Repo: github.com/wickednull/netwatch

