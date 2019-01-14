import csv
import json
import random
import os

from DBDSniffer.QueuedOutput import QueuedOutput
from Utilities import configuration as config
from pathlib import Path


class Killer:
    killers = []
    killer_perks = []
    killer_addons = {}
    __instance = None

    current_killer_portrait_path = ""

    def __new__(cls):
        if Killer.__instance is None:
            Killer.__instance = object.__new__(cls)
        return Killer.__instance

    def __init__(self):
        self.killers = self.get_killers()
        self.killer_perks = self.get_killer_perks()
        self.killer_addons = self.get_killer_addons()

    @staticmethod
    def get_random_killer_portrait():
        return random.choice(list(dict(config.config.items('killer_portraits')).keys()))

    @staticmethod
    def get_killers():
        killers = list(json.load(open(config.get('killer', 'killer_json'))).values())
        return killers

    @staticmethod
    def get_killer_vars():
        killers = list(json.load(open(config.get('killer', 'killer_vars_json'))).values())
        return killers

    @staticmethod
    def get_killer_perks():
        killer_perks = list(json.load(open(config.get('killer', 'killer_perks_json'))).values())
        return killer_perks

    @staticmethod
    def get_killer_addons():
        killer_perks = json.load(open(config.get('killer', 'killer_addons_json')))
        return killer_perks

    @staticmethod
    def get_killer_portrait_path(killer_name):
        portrait_path = config.get('dbd', 'character_portrait_path')
        killer_portrait = config.get('killer_portraits', killer_name)
        killer_portrait_path = "{portrait_path}{separator}{killer_portrait}".format(portrait_path=portrait_path, separator=os.sep, killer_portrait=killer_portrait)

        killer_portrait_file = Path(killer_portrait_path)
        if killer_portrait_file.is_file():
            print("Getting Killer Portrait: {}".format(killer_portrait_path))
            return killer_portrait_path
        print("Could not get Killer Portrait: {}".format(killer_portrait_path))
        return ""

    def check_for_killer_addons(self, packet_str):
        killer_addon_detected = False

        for killer_addon in self.killer_addons:
            for addon in self.killer_addons[killer_addon]:
                if addon in packet_str:
                    killer_addon_detected = True
                    current_killer_portrait_path = self.get_killer_portrait_path(killer_addon)
                    QueuedOutput().queue_print("Detected Addon ({}): {}".format(killer_addon, addon))

        return killer_addon_detected

    def check_for_killer(self, packet_str):
        for killer in self.get_killers():
            if any(substring in packet_str for substring in self.killers[killer]):
                QueuedOutput().queue_print("***Detected Killer***: {}".format(killer))
                return killer

        return ""

    def test_class(self):
        import pprint as pp
        pp.pprint(self.killer_perks)
        pp.pprint(self.get_killer_addons())


# Test Run
if __name__ == '__main__':
    killer = Killer()
    killer.test_class()
