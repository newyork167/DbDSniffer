import csv
import json
import random
import os

from DBDSniffer.QueuedOutput import QueuedOutput
from DBDSniffer.Singleton import Singleton
from DBDSniffer.TkAppThreadedVars import ThreadedVars
from Utilities import configuration as config
from pathlib import Path


class Bunch(object):
    def __init__(self, adict):
        self.__dict__.update(adict)


@Singleton
class Killer:
    killers = []
    killer_perks = []
    killer_addons = {}

    def __init__(self):
        self.killers = self.get_killers()
        self.killer_perks = self.get_killer_perks()
        self.killer_addons = self.get_killer_addons()
        locals().update(self.get_killer_vars())

    @staticmethod
    def get_random_killer_portrait():
        return random.choice(list(dict(config.config.items('killer_portraits')).keys()))

    @staticmethod
    def get_killers():
        killers = json.load(open(config.get_with_root_dir('killer', 'killer_json')))
        return killers

    @staticmethod
    def get_killer_vars():
        killers = dict(json.load(open(config.get_with_root_dir('killer', 'killer_vars_json'))))
        return killers

    @staticmethod
    def get_killer_perks():
        killer_perks = list(json.load(open(config.get_with_root_dir('killer', 'killer_perks_json'))).values())
        return killer_perks

    @staticmethod
    def get_killer_addons():
        killer_perks = json.load(open(config.get_with_root_dir('killer', 'killer_addons_json')))
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

        for killer in self.killer_addons:
            for addon in self.killer_addons[killer]:
                if addon in packet_str:
                    killer_addon_detected = True
                    ThreadedVars.instance().current_killer_portrait_path = self.get_killer_portrait_path(killer)
                    QueuedOutput.instance().queue_print("Detected Addon ({}): {}".format(killer, addon))

        return killer_addon_detected

    def check_for_killer(self, packet_str):
        for killer in self.get_killers():
            if any(substring in packet_str for substring in self.killers[killer]):
                QueuedOutput.instance().queue_print("***Detected Killer***: {}".format(killer))
                return killer

        return ""
