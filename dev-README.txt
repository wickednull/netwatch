Here is a comprehensive list of functions and features included in the NetWatch Toolkit v2.3:

⸻

🔧 Core Functions
	•	Root Check (is_root()): Ensures script is run with root privileges.
	•	Interface Detection: Automatically detects default network interface.
	•	MAC Resolution: Retrieves MAC address for a given IP (get_mac()).

⸻

🧭 GUI Overview
	•	Cyberpunk-styled GUI using tkinter and ttk
	•	Tabbed layout with vertical side-tabbed navigation
	•	Real-time log output for every tool in its respective tab

⸻

🛠️ Toolkit Features (By Tab)

1. Nmap Scanner
	•	TCP SYN stealth scan (nmap -sS)
	•	Input: IP address or CIDR range
	•	Real-time output of open ports and services

⸻

2. ARP Scanner
	•	Active ARP discovery across local network
	•	Lists live hosts and their MAC addresses

⸻

3. ARP Spoofing
	•	MITM attack between a target and gateway
	•	Sends continuous spoofed ARP replies to poison cache
	•	Start/Stop controls for persistent spoofing

⸻

4. ARP Kick
	•	Sends invalid ARP replies to disconnect a device
	•	Configurable packet count (default: 150)
	•	Designed to kick devices off a network without permanent damage

⸻

5. Traceroute
	•	Runs traceroute to trace the route to a target host
	•	Visualizes hops and network paths

⸻

6. Reverse Shell Listener
	•	Launches a terminal-based netcat listener on specified port
	•	Prepares for incoming reverse shells

⸻

7. Evil Portal
	•	Creates a fake WiFi access point with:
	•	Custom SSID
	•	Captive portal (uses custom HTML or default login form)
	•	Captures credentials submitted by users
	•	Stores captured data in netwatch_portal/credentials.txt
	•	Includes interface/AP setup and iptables redirection
	•	Start/Stop + View captured creds buttons

⸻

8. Deauth Attack
	•	Sends 802.11 deauthentication frames
	•	Requires wireless interface in monitor mode
	•	Forces disconnection of specified client MAC from AP

⸻

9. DNS Spoofing
	•	Injects DNS spoofing rules into dnsmasq
	•	Redirects specific domains to malicious IPs

⸻

10. Bandwidth Monitor
	•	Launches iftop in terminal for live traffic monitoring
	•	Useful for bandwidth usage and connection inspection

⸻

11. Packet Capture
	•	Uses tcpdump to capture packets into .pcap files
	•	Interface and file name configurable
	•	Launches in terminal

⸻

12. MAC Changer
	•	Changes MAC address of a specified interface
	•	Option to set a specific MAC or randomize it
	•	Uses macchanger

⸻

13. Firewall Rule Manager
	•	Adds iptables rules via GUI
	•	Simple rule entry interface
	•	Example: -A INPUT -p tcp --dport 80 -j ACCEPT

⸻

14. Exploit Launcher (Metasploit Integration)
	•	Launches msfconsole with an .rc script
	•	Supports:
	•	Exploit path
	•	RHOST, LHOST
	•	LPORT
	•	Automates Metasploit exploit launch in terminal

⸻

15. Session Log Export
	•	Exports all tab outputs/logs to a single log file
	•	Default filename: netwatch_session.log

⸻

16. Reset Tab
	•	Clears all input fields across all tabs
	•	Quick reset to prepare for new session

⸻

17. Session Manager
	•	Save current session input values
	•	Load saved session later
	•	Helpful for repeat testing or live demonstrations

⸻

📁 Storage
	•	Captured credentials: netwatch_portal/credentials.txt
	•	HTML landing pages: Saved to netwatch_portal/index.html
	•	Exported logs: netwatch_session.log
	•	Saved session input: netwatch_session.txt

⸻

🧱 Dependencies
	•	Python 3.x
	•	scapy
	•	nmap
	•	tkinter
	•	netcat
	•	hostapd, dnsmasq
	•	iftop, tcpdump, macchanger
	•	iptables
	•	metasploit-framework (optional)
