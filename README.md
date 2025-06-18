# netwatch WORK IN PROGRESS
Offensive and diagnostic toolkit with ARP scanning, spoofing, port scanning, sniffing, traceroute, reverse shell, and an Evil Portal phishing server — all packed into a single cyberpunk-themed Python GUI.

# NetWatch Toolkit v2
# NetWatch Dev

**Author:** wickedNull  
**Version:** 2.0  
**License:** For Educational Use Only

NetWatch is an advanced Python-based network analysis and attack toolkit with a cyberpunk-themed graphical interface. It includes essential tools for scanning, spoofing, packet injection, reverse shells, and phishing portal deployment — all in a simple GUI.

> ⚠️ **Disclaimer:** This toolkit is for **educational and authorized testing** purposes only. Unauthorized use is illegal and unethical. You are solely responsible for how you use this software.

---

## 🧰 Features

- **Nmap Scanner** – Perform stealth SYN scans (`nmap -sS`) on targets.
- **ARP Scanner** – Discover devices on the network using ARP requests.
- **ARP Spoofing** – Intercept communication between hosts by poisoning ARP tables.
- **Traceroute** – Analyze the network path to a target host.
- **Reverse Shell Listener** – Open a Netcat listener on a port of your choice.
- **Evil Portal** – Serve a phishing login page and capture credentials.
- **Deauthentication Attack** – Kick devices off a Wi-Fi network using crafted packets.
- **Reset Panel** – Clears all input fields in the GUI in one click.

---

## 📦 Requirements

Make sure the following are installed on your system:

- Python 3.x
- [`scapy`](https://pypi.org/project/scapy/)
- `nmap`
- `tkinter` (usually included with Python)
- `hostapd` and `dnsmasq` *(for full Evil Portal functionality)*
- `netcat` (also called `nc`)
- `gnome-terminal` *(for launching reverse shell listeners in a new window)*

### Install Python requirements:

```bash
pip3 install scapy

🚀 Usage

Run the toolkit with root privileges:

sudo python3 netwatchV2.py

or to run recent dev. releases

Run thetoolkit with root privileges :

sudo python3 netwatch.py

Some modules like ARP Spoofing and Deauth require sudo and compatible network interfaces (e.g., monitor mode enabled).

🔐 Evil Portal Module
	•	Starts a fake login page on port 8080.
	•	Captures submitted usernames and passwords.
	•	Saves captured credentials to:
netwatch_portal/credentials.txt

⚔️ Deauth Attack Module

Send deauthentication packets to disconnect a client from a wireless network.

Required:
	•	A wireless adapter capable of monitor mode and packet injection.
	•	Interface name like wlan0mon.

Example setup:
sudo ip link set wlan0 down
sudo iwconfig wlan0 mode monitor
sudo ip link set wlan0 up

Enter the interface, target MAC, and AP MAC in the GUI and launch the attack.

🔁 Reset Tab
Use the Reset tab to instantly clear all fields in every tab of the GUI. Ideal for refreshing the interface between operations.

📁 Directory Structure

netwatchV2.py
netwatch_portal/
├── credentials.txt       # Captured portal credentials
└── index.html            # Custom HTML phishing page (optional)

📌 Notes
	•	All output appears in themed text areas in the GUI.
	•	Multi-threaded where needed to prevent freezing the GUI.
	•	Evil Portal uses Python’s built-in http.server to avoid external web servers.

⸻

⚠️ Legal Notice

This software is provided for educational and ethical penetration testing only. Any misuse, unauthorized access, or attacks on networks you do not own or have permission to audit may result in legal consequences.

You have been warned. Use responsibly.

⸻

🤝 Contributions

Feel free to fork, improve, and contribute to NetWatch. Pull requests are welcome, especially for:
	•	New attack modules
	•	GUI enhancements
	•	Cross-platform compatibility improvements
	•	Automation tools and logs

⸻

📬 Contact

For inquiries, collaboration, or bug reports, feel free to reach out or open an issue on GitHub.

