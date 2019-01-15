import json
import os
from os import listdir
from os.path import isfile, join

import Utilities.configuration as config


def get_killer_folders(addon_path):
    return [x[0] for x in os.walk(addon_path) if x[0] != addon_path]


def get_addons_from_folder(folder):
    return [f for f in listdir(folder) if isfile(join(folder, f))]


def build_addons():
    killer_addons = {}
    killer_folders = get_killer_folders(config.get_with_root_dir('utilities', 'addon_folder_path'))
    for folder in killer_folders:
        killer = folder.split('\\')[-1]
        addons = get_addons_from_folder(folder)
        addons = [a.split('iconAddon_')[-1].split('.')[0] for a in addons]
        addons = [a.lower() for a in addons]
        killer_addons[killer] = addons

    with open(config.get_with_root_dir('killer', 'killer_addons_json'), 'w+') as json_output_file:
        json_output_file.write(json.dumps(killer_addons))


if __name__ == '__main__':
    build_addons()
