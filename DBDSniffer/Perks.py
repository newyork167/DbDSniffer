from queue import Queue
from DBDSniffer import Killer
from DBDSniffer import QueuedOutput
from Utilities import utilities, configuration as config
import re


class Perks:
    perksQueue = Queue()

    @staticmethod
    def check_for_killer_perk(packet_str):
        k_perks = [m.start() for m in re.finditer('killerperk', packet_str)]

        if len(k_perks) > 0:
            for k_perk_pos in k_perks:
                killer_perk_string = packet_str[k_perk_pos:].split('\\x')[0]
                QueuedOutput().queue_print("Found killer perk - " + killer_perk_string)
                utilities.output_to_file("Found killer perk: {}".format(killer_perk_string), packet_str)
            return True
        return False

    @staticmethod
    def check_for_survivor_perk(packet_str):
        k_perks = [m.start() for m in re.finditer('survivorperk', packet_str)]

        if len(k_perks) > 0:
            for k_perk_pos in k_perks:
                survivor_perk_string = packet_str[k_perk_pos:].split('\\x')[0]
                QueuedOutput().queue_print("Found survivor perk - " + survivor_perk_string)
                utilities.output_to_file("Found surivor perk: {}".format(survivor_perk_string), packet_str)
            return True
        return False

    @staticmethod
    def check_for_perks(packet_str):
        perk_detected = False

        for perk in Killer().killer_perks:
            if perk in packet_str:
                perk_detected = True
                QueuedOutput().queue_print("Detected Perk: {}".format(perk))
                utilities.output_to_file("Detected Perk: {}".format(perk), packet_str)

        return perk_detected
