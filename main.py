from scapy.all import *
from threading import Thread, Event
from time import sleep
import platform
from tkinter import Tk, Label, Button
import tkinter as tk
import threading
import sys

print(platform.architecture())

os_platform = platform.system()

if os_platform == "Darwin":
    interfaces = [{"name": "en0"}]
elif "win" in os_platform.lower():
    interfaces = [i for i in scapy.arch.get_windows_if_list() if 'vmware' not in i['name'].lower()]
else:
    interfaces = [{"name": "eth0"}]


current_ip = ""
packet_log = []
last_packet = ""


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
        global last_packet
        ip_layer = packet.getlayer(IP)
        ip_dest = ip_layer.dst
        ip_src = ip_layer.src

        packet_log.append(packet)

        for p in packet_log:
            ip_layer = packet.getlayer(IP)
            ip_dest = str(ip_layer.dst)
            ip_src = str(ip_layer.src)

            if current_ip in (ip_src, ip_dest) and ip_layer.payload.dport in (80, 443):
                try:
                    # print(hexdump(p[TCP].payload))
                    last_packet = hexdump(p[TCP].payload)
                except Exception as ex:
                    print(ex)
        if last_packet != "" and last_packet is not None:
            print(last_packet)


def startSniffer():
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


class App(threading.Thread):
    entryBox = None

    def __init__(self, tk_root):
        global last_packet
        self.root = tk_root

        self.LABEL = Label(ROOT, text="Hello, world!")
        self.LABEL.pack()

        self.ip_label = Label(self.root, text="Please Input IP")
        self.ip_label.pack()

        self.entryBox = tk.Entry(self.root, bd=5)
        self.entryBox.pack()

        self.close_button = Button(self.root, text="Close", command=self.quit)
        self.close_button.pack()

        self.last_packet_label = Label(self.root, text=last_packet)
        self.last_packet_label.pack()

        self.t1 = threading.Thread(target=startSniffer)
        self.t1.start()

        threading.Thread.__init__(self)
        self.start()

    def run(self):
        global current_ip, last_packet
        loop_active = True
        while loop_active:
            if current_ip != self.entryBox.get():
                current_ip = self.entryBox.get()
                print("Currently looking for packets from {}".format(current_ip))
            self.LABEL = Label(self.root, text=last_packet)
            self.LABEL.pack()
            self.root.update()

    def quit(self):
        self.t1.join(2.0)
        sys.exit(0)

ROOT = Tk()
APP = App(ROOT)
ROOT.mainloop()
