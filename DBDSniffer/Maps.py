import re
from DBDSniffer.QueuedOutput import QueuedOutput


class Maps:
    game_maps = {
        "Haddonfield": ['blueprints/props/05-suburbs/bp_streetpatch'],
        "Asylum": ['blueprints/props/04-asylum/bp_asy_'],
        "Red Forest": ['blueprints/props/08-boreal'],
        'Junkyard': ['blueprints/props/02-junkyard'],
        "Swamp": ['blueprints/props/06-swamp'],
        "MacMillan Estate": ['blueprints/props/walls/bp_wallarrangement04_in'],
        "Slaughterhouse": ['blueprints/gameplayelements/worldobjects/windowblockers/bp_boardedwindow_slaughter1'],
        "Coldwind Farm": ['blueprints/props/walls/bp_farm_wall01']
    }

    def check_map(self, packet_str):
        map_detected = False

        for game_map in self.game_maps:
            if any(gm in packet_str for gm in self.game_maps[game_map]):
                map_detected = True
                QueuedOutput().queue_print("Detected Map: {}".format(game_map))

        map_list = [m.start() for m in re.finditer('/map', packet_str)]

        if len(map_list) > 0:
            for ml in map_list:
                ml_string = packet_str[ml:].split('\\x')[0]
                QueuedOutput().queue_print("Detected Map Component?: {}".format(ml_string))

        return map_detected
