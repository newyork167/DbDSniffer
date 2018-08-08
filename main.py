from scapy.all import *
from threading import Thread, Event
from time import sleep

interfaces = [i for i in scapy.arch.get_windows_if_list() if 'vmware' not in i['name'].lower()]


class Sniffer(Thread):
    def __init__(self, interface=interfaces[0]['name']):
        super().__init__()

        self.daemon = True

        self.socket = None
        self.interface = interface
        self.stop_sniffer = Event()

    def run(self):
        self.socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=self.interface,
            filter="ip"
        )

        sniff(
            opened_socket=self.socket,
            prn=self.print_packet,
            stop_filter=self.should_stop_sniffer
        )

    def join(self, timeout=None):
        self.stop_sniffer.set()
        super().join(timeout)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    @staticmethod
    def print_packet(packet):
        ip_layer = packet.getlayer(IP)
        ip_dest = ip_layer.dst
        ip_src = ip_layer.src
        print("[!] New Packet: {src} -> {dst}\n\t{data}".format(src=ip_src, dst=ip_dest, data=packet))


sniffer = Sniffer()

print("[*] Start sniffing...")
sniffer.start()

try:
    while True:
        sleep(100)
except KeyboardInterrupt:
    print("[*] Stop sniffing")
    sniffer.join(2.0)

    if sniffer.isAlive():
        sniffer.socket.close()