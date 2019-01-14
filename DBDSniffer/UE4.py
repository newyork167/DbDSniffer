import re

from DBDSniffer.QueuedOutput import QueuedOutput


class UE4:
    __instance = None

    def __new__(cls):
        if UE4.__instance is None:
            UE4.__instance = object.__new__(cls)
        return UE4.__instance

    def check_for_blueprints(self, packet_str):
        blueprint_list = [m.start() for m in re.finditer('blueprint', packet_str)]

        if len(blueprint_list) > 0:
            for bp in blueprint_list:
                bp_string = packet_str[bp:].split('\\x')[0]
                # if all(check_str not in packet_str for check_str in ['statuseffects', 'survivorperks', 'killerperks', 'gameplayelements']):
                if 'statuseffects' not in bp_string and 'perkconditions' not in bp_string and 'survivorperks' not in bp_string and 'killerperks' not in bp_string:
                    if 'itemaddons' in bp_string:
                        QueuedOutput.instance().queue_print('\tFound addon: {}'.format(bp_string))
                    else:
                        QueuedOutput.instance().queue_print("\t\t - " + bp_string)

            return True

        character_list = [m.start() for m in re.finditer('characters', packet_str)]

        if len(character_list) > 0:
            for cl in character_list:
                cl_string = packet_str[cl:].split('\\x')[0]
                QueuedOutput.instance().queue_print("Character Data Found: " + cl_string)

        return False

    def check_for_other(self, packet_str):
        re_format = "name="

        name_list = [m.start() for m in re.finditer(re_format, packet_str)]
        if len(name_list) > 0:
            for name in name_list:
                print(name)
