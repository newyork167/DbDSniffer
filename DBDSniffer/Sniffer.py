from scapy.all import *
from threading import Thread, Event
import time
from scapy.layers.inet import IP, UDP
from DBDSniffer import Killer
from DBDSniffer import Maps
from DBDSniffer import Network
from DBDSniffer import Perks
from DBDSniffer import QueuedOutput
from DBDSniffer.TkApp import App
from DBDSniffer import UE4


class Sniffer(Thread):
    ip_killer_detected = {}
    killer_ip = 0
    last_killer_ip = '0'
    paused = False
    last_killer_ip_time = 0
    killer_ping = 0

    @staticmethod
    def current_milli_time():
        return int(round(time.time() * 1000))

    def __init__(self, c_queue=None, interface=Network().interfaces[0]['name']):
        super().__init__()

        if c_queue is None:
            c_queue = QueuedOutput().console_queue

        self.daemon = True
        self.queue = c_queue
        self.socket = None
        self.interface = interface
        self.stop_sniffer = Event()

    def pause(self):
        self.paused = True

    def unpause(self):
        self.paused = False

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
        return False

    def check_for_stun_packet(self, packet):
        ip_layer = packet.getlayer(IP)
        ip_dest = ip_layer.dst
        ip_src = ip_layer.src

        packet_is_stun_packet = False

        if len(packet[UDP].payload) == 56:
            packet_is_stun_packet = True
            self.last_killer_ip_time = self.current_milli_time()
        elif len(packet[UDP].payload) == 68:
            packet_is_stun_packet = True
            # Determine ping to killer
            current_time = self.current_milli_time()
            current_killer_ping = current_time - self.last_killer_ip_time
            if current_killer_ping > 10:
                # print("Killer ping: {}".format(killer_ping))
                self.killer_ping = current_killer_ping

        if packet_is_stun_packet:
            # Handle showing IP found from STUN protocol
            if ip_dest == Network().local_ip_address:
                self.killer_ip = str(ip_src)
            else:
                self.killer_ip = str(ip_dest)
            return True
        return False

    def print_packet(self, packet):
        print(packet)
        if self.paused:
            return

        ip_layer = packet.getlayer(IP)

        # for p in packet_log:
        if UDP in packet:
            dport = ip_layer.payload.dport
            sport = ip_layer.payload.sport

            port_min = 40000
            port_max = 65535

            self.check_for_stun_packet(packet)

            if port_max > dport > port_min or port_max > sport > port_min:
                packet_str = str(packet).lower()
                self.handle_packet(packet_str)

    @staticmethod
    def handle_packet(packet_str):
        try:
            killer_detected = Killer().check_for_killer(packet_str=packet_str)

            perk_detected = Perks().check_for_perks(packet_str=packet_str)

            killer_addon_detected = Killer().check_for_killer_addons(packet_str=packet_str)

            # killer_perk_detected = check_for_killer_perk(packet_str=packet_str)

            # survivor_perk_detected = check_for_survivor_perk(packet_str=packet_str)

            extra_detected = UE4().check_for_blueprints(packet_str=packet_str)

            map_detected = Maps().check_map(packet_str=packet_str)

            out_of_lobby_or_match_finished = Network.detect_lobby_finished(packet_str=packet_str)

            if killer_detected:
                current_killer_portrait_path = Killer().get_killer_portrait_path(killer_detected)

            if out_of_lobby_or_match_finished and App().clear_portrait_and_perks_list is False:
                clear_portrait_and_perks_list = True
                QueuedOutput().queue_print("Left Lobby/Match")

        except Exception as ex:
            print(ex)
