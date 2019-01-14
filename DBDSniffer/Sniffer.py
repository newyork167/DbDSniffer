from scapy.all import *
from threading import Thread, Event
import time
from scapy.layers.inet import IP, UDP
from DBDSniffer import Killer
from DBDSniffer import Maps
from DBDSniffer import Network
from DBDSniffer import Perks
from DBDSniffer import QueuedOutput
from DBDSniffer import UE4
from DBDSniffer.TkAppThreadedVars import ThreadedVars
from Utilities.configuration import config


class Sniffer(Thread):
    ip_killer_detected = {}
    killer_ip = 0
    last_killer_ip = '0'
    paused = False
    last_killer_ip_time = 0
    killer_ping = 0
    socket = None
    last_stun_check_time = datetime.now()
    __instance = None

    def __new__(cls):
        if Sniffer.__instance is None:
            Sniffer.__instance = object.__new__(cls)
        return Sniffer.__instance

    @staticmethod
    def current_milli_time():
        return int(round(time.time() * 1000))

    def __init__(self, c_queue=None, interface=Network.instance().interfaces[0]['name']):
        super().__init__()

        if c_queue is None:
            c_queue = QueuedOutput().console_queue

        self.daemon = True
        self.queue = c_queue
        self.interface = interface
        self.stop_sniffer = Event()

    def pause(self):
        self.paused = True

    def unpause(self):
        self.paused = False

    def run(self):
        port_filter = 'udp and portrange {}-{}'.format(
            config.getint('network', 'port_min'),
            config.getint('network', 'port_max')
        )
        sniff(filter=port_filter, prn=self.print_packet, store=0)

    def join(self, timeout=None):
        self.stop_sniffer.set()
        super().join(timeout)

    def should_stop_sniffer(self, packet):
        return False

    def check_for_stun_packet(self, packet):
        seconds_since_last_check = (datetime.now() - self.last_stun_check_time).total_seconds()
        if seconds_since_last_check > config.getint('network', 'stun_check_interval_seconds'):
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
                    ThreadedVars.instance().killer_ping = current_killer_ping

            if packet_is_stun_packet:
                # Handle showing IP found from STUN protocol
                if ip_dest == Network.instance().local_ip_address:
                    ThreadedVars.instance().killer_ip = str(ip_src)
                else:
                    ThreadedVars.instance().killer_ip = str(ip_dest)
                return True
        return False

    def print_packet(self, packet):
        with open(config.get('output', 'output_file'), 'a') as output_file:
            output_file.write(str(packet))
            output_file.write("\n")

        if self.paused:
            return

        try:
            # for p in packet_log:
            if UDP in packet:
                ip_layer = packet.getlayer(IP)
                dport = ip_layer.payload.dport
                sport = ip_layer.payload.sport

                port_min = 40000
                port_max = 65535

                self.check_for_stun_packet(packet)

                if port_max > dport > port_min or port_max > sport > port_min:
                    packet_str = str(packet).lower()
                    self.handle_packet(packet_str)
        except Exception as ex:
            pass

    @staticmethod
    def handle_packet(packet_str):
        try:
            killer_detected = Killer.instance().check_for_killer(packet_str=packet_str)

            perk_detected = Perks().check_for_perks(packet_str=packet_str)

            killer_addon_detected = Killer.instance().check_for_killer_addons(packet_str=packet_str)

            # killer_perk_detected = check_for_killer_perk(packet_str=packet_str)

            # survivor_perk_detected = check_for_survivor_perk(packet_str=packet_str)

            extra_detected = UE4.UE4().check_for_blueprints(packet_str=packet_str)

            other_detected = UE4.UE4().check_for_other(packet_str=packet_str)

            map_detected = Maps.Maps().check_map(packet_str=packet_str)

            out_of_lobby_or_match_finished = Network.instance().detect_lobby_finished(packet_str=packet_str)

            if killer_detected:
                current_killer_portrait_path = Killer.instance().get_killer_portrait_path(killer_detected)

            if out_of_lobby_or_match_finished and ThreadedVars.instance().clear_portrait_and_perks_list is False:
                ThreadedVars.instance().clear_portrait_and_perks_list = True
                QueuedOutput().queue_print("Left Lobby/Match")

        except Exception as ex:
            print("Handle Packet: {}".format(ex))
