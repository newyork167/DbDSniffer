from scapy.all import *
from threading import Thread, Event
from time import sleep
import platform
from tkinter import Tk, Label, Button
import tkinter as tk
import threading
import sys
import re
import string

print(platform.architecture())

os_platform = platform.system()

output_file = open('output.txt', 'w+')

if os_platform == "Darwin":
    interfaces = [{"name": "en0"}]
elif "win" in os_platform.lower():
    interfaces = [i for i in scapy.arch.get_windows_if_list() if 'vmware' not in i['name'].lower()]
else:
    interfaces = [{"name": "eth0"}]


current_ip = ""
packet_log = []
last_packet = ""
substring_list = ('_leg', 'game', '_torso', '_head', 'item_', 'blueprint', 'map')

survivors = {
    "Ace Visconti": ['av_head0', 'av_legs', 'av_torso'],
    "Bill Overbeck": ['bo_head0, bo_legs0', 'bo_torso0'],
    "Claudette Morrelle": ['c_head0', 'c_legs0', 'c_torso0', 'cm_head0', 'cm_legs0', 'cm_osj', 'cm_torso0'],
    "Dwight Fairfield": ['d_head0', 'd_legs0', 'd_torso0', 'df_head0', 'df_legs0', 'df_torso0'],
    "David King": ['dk_head0', 'dk_legs0', 'dk_torso0'],
    "Feng Min": ['fm_head0', 'fm_legs0', 'fm_torso0'],
    "David Trapp": ['fs_head0', 'fs_legs0', 'fs_torso0'],
    "Kate Denson": ['gs_head0', 'gs_legs0', 'gs_torso0'],
    "Jake Park": ['j_head0', 'j_legs0', 'j_torso0', 'jp_head0', 'jp_legs0', 'jp_torso0'],
    "Laurie Strode": ['ls_torso0', 'ls_legs0', 'ls_head0'],
    "Meg Thomas": ['m_head0', 'm_legs0', 'm_torso0', 'mt_head0', 'mt_legs0', 'mt_mask', 'mt_rtlh', 'mt_torso0']
}

killers = {
    "Huntress": ['be_body', 'be_mask', 'be_w0', 'bear_outfit'],
    "Cannibal": ['ca_body', 'ca_head0'],
    "Hillbilly": ['crooked_body', 'crooked_legs', 'hb_legs', 'hb_torso', 'tc_body', 'tc_w0', 'hillbilly_'],
    "Doctor": ['do_body', 'do_head', 'do_torso', 'killer07_', 'chuckles_', 'dow0', 'do_w0', 'do_weapon'],
    "Pig": ['fk_body', 'fk_mask', 'fk_w0'],
    "Clown": ['gk_body', 'gk_head', 'gk_w0'],
    "Hag": ['ha_body', 'ha_claw', 'ha_head', 'wi_body', 'witch_outfit', 'wi_hair', 'wi_w0'],
    "Michael Myers": ['mm_head0'],
    "Nurse": ['nr_body', 'nr_head', 'nurse_body', 'nurse_head', 'nurse_weapon', 'nurse_outfit', 'smile', 'tn_body', 'tn_head', 'tn_w0'],
    "Freddy Kreuger": ['sd_body', 'sd_head', 'sd_w0'],
    "Trapper": ['tr_body', 'tr_head', 'trapper_body', 'trapper_head', 'trw0', 'tr_mask', 's01_body', 's01_head', 's01_weapon'],
    "Wraith": ['tw_head', 'wr_body', 'wr_head', 'wraith_body', 'wraith_body', 'bob_outfit'],
}

killer_perks = [
    'agitation',
    'bbqandchili',
    'bbqandchilli',
    'barbecueandchili',
    'barbecueandchilli',
    'bittermurmur',
    'bloodhound',
    'brutalstrength',
    'deerstalker',
    'distressing',
    'enduring',
    'franklin',
    'fireup',
    'firedup',
    'insidious',
    'irongrasp',
    'iron_grasp',
    'lightborn',
    'nooneescapesdeath',
    'no_one_escapes_death',
    'nursescalling',
    'nursecalling',
    'predator',
    'rememberme',
    'shadowborn',
    'sloppybutcher',
    'spiesfromtheshadows',
    'stridor',
    'thanatophobia',
    'thrillofthehunt',
    'thrill_of_the_hunt',
    'tinkerer',
    'underperform',
    'unnervingpresence',
    'unrelenting',
    'whispers',
    'hex_ruin',
    'tenacity'
]

killer_addons = {
    "Clown": ['bottleofcholororm', 'cheapginbottle', 'cigarbox', 'ether5', 'ether10', 'ether15', 'fingerlessparadegloves', 'flaskofbleach',
              'garishmakeupkit', 'kerosenecan', 'redheadspinkyfinger', 'robinfeather', 'smellyinnersoles', 'solventjug', 'starlingfeather',
              'stickysodabottle', 'sulfuricacidvial', 'tattoosmiddlefinger', 'thickcorkstopper', 'vhsporn',
              ],
    "Nurse": ['badmankeepsake', 'badmanslastbreath', 'campbellslastbreath', 'catatonictreasure', 'darkcincture',
              'dullbracelet', 'fragilewheeze', 'ataxicrespiration', 'anxiousgasp', 'heavypanting', 'jennerslastbreath', 'kavanaghslastbreath',
              'matchbox', 'metalspoon', 'plaidflannel', 'pocketwatch', 'spasmodicbreath', 'tornbookmark', 'whitenitcomb', 'woodenhorse'
              ],

    "Wraith": ['bloodblindwarrior', 'bloodblink', 'krafabai', 'windstorm', 'boneclapper', 'coxcombedclapper', 'mudallseeing',
               'mudbaikrakaeug', 'mudkrafabai', 'mudswifthunt', 'mudwindstorm', 'sootbaikrakaeug', 'sootkratin',
               'sootkuntintakkho', 'spiritallseeing', 'spiritblindwarrior', 'whiteallseeing', 'whiteblindwarrior', 'whitekuntintakkho'
               'whitetheghost', 'whitewindstorm'
               ],

    "Trapper": ['bloodycoil', 'diamondstone', 'honingstone', 'logwooddye', 'oilycoil', 'paddedjaws', 'rustedjaws',
                'secondarycoil', 'serratedjaws', 'settingtools', 'stitchedbag', 'tapsetters', 'trapsetters',
                'tarbottle', 'trapperbag', 'trappergloves', 'trappersack', 'waxbrick'
                ],

    "Cannibal/Leatherface": ['carburetortuningguide', 'chainsawfile', 'chainsbloody', 'chainsgrisly', 'chainsrusted', 'depthgaugerake',
                             'homemademuffler', 'lightchassis', 'longguidebar', 'primerbulb', 'shoplubricant', 'sparkplug', 'speedlimiter',
                             'vegetableoil', 'awardwinningchili', 'chili', 'knifescratches', 'thebeastsmark', 'thegrease'
                             ],

    "Hillbilly": ['deathengravings', 'doomengravings', 'spikedboots', 'thethompsonsmix', 'thompsonsmoonshine', 'primerbulb'],

    "Michael Myers": ['blondehair', 'boyfriendsmemo', 'deadrabbit', 'glassfragment', 'hairbow', 'hairbrush', 'jewelry',
                       'jewelerybox', 'jmyersmemorial', 'judithsjournal', 'judithstombstone', 'lockofhair', 'memorialflower',
                       'mirrorshard', 'reflectivefragment', 'scratchedmirror', 'tackyearrings', 'tombstonepiece', 'tuftofhair', 'vanitymirror'
                       ],

    "Hag": ['bloodiedmud', 'bloddiedwater', 'bogwater', 'crackedturtleegg', 'cypressnecklet', 'deadflymud', 'disfiguredear', 'dragonflywings',
            'driedcicada', 'granmasheart', 'halfeggshell', 'mintrag', 'powderedeggshell', 'pussywillowcatkins', 'ropenecklet', 'rustyshackles',
            'scarredhand', 'swamporchidnecklace', 'waterloggedshoe', 'willowwreath'
            ],

    "Doctor": ['calmcartersnotes', 'calmclass', 'diciplinecartersnotes', 'diciplineclass', 'diciplineclass', 'highstimuluselectrode', 'interviewtape',
               'iridescentking', 'mapleknight', 'moldyelectrode', 'obediencecartersnotes', 'ordercartersnotes', 'orderclass', 'polishedelectrode',
               'restraintcartersnotes', 'restraintclass', 'scrappedtape', 'cartersnotes'
               ],

    "Huntress": ['amanitatoxin', 'bandagedhaft', 'begrimedhead', 'berustoxin', 'coarsestone', 'deerskingloves', 'finestone', 'flowbabushka',
                 'glowingconcoction', 'infantrybelt', 'iridescenthead', 'leatherloop', 'mannagrassbraid', 'oakhaft', 'pungentfiale', 'rustyhead',
                 'shinypin', 'venomousconcoction', 'yewseedbrew', 'yewseedconcoction',
                 ],

    "Freddy Kreguer": ['blackbox', 'bluedress', 'catblock', 'classphoto', 'gardenrake', 'greendress', 'jumprope', 'kidsdrawing',
                       'nancysmasterpiece', 'nancyssketch', 'outdoorrope', 'paintthinner', 'pillbottle', 'prototypeclaw', 'redpaintbrush', 'sheepblock',
                       'swingchains', 'unicornblock', 'woolshirt', 'zblock'
                       ],

    "Pig": ['amandasletter', 'amandassecret', 'bagofgears', 'combatstraps', 'crateofgears', 'facemask', 'interlockingrazor', 'jigsawannotagedplan',
            'jigsawsketch', 'johnsmedicalfile', 'lastwill', 'razerwire', 'rulessetn2', 'rustyattachments', 'shatteredsyringe', 'slowreleasetoxin',
            'tamperedtimer', 'utilityblades', 'videotape', 'workshopgrease',
            ]
}

game_maps = {
    "Haddonfield": ['blueprints/props/05-suburbs/bp_streetpatch'],
    "Asylum": ['blueprints/props/04-asylum/bp_asy_']
}

start_ordinal_lower = 0x05
start_ordinal_upper = 0x85
ordinal_step = 0x4
chat_map_lower = dict(zip(string.ascii_lowercase, [x for x in range(start_ordinal_lower, start_ordinal_lower + len(string.ascii_lowercase) * ordinal_step, ordinal_step)]))
chat_map_upper = dict(zip(string.ascii_uppercase, [x for x in range(start_ordinal_upper, start_ordinal_upper + len(string.ascii_lowercase) * ordinal_step, ordinal_step)]))

chat_map = {**chat_map_lower, **chat_map_upper}


def check_for_survivor_perk(packet_str):
    k_perks = [m.start() for m in re.finditer('survivorperk', packet_str)]

    if len(k_perks) > 0:
        for k_perk_pos in k_perks:
            survivor_perk_string = packet_str[k_perk_pos:].split('\\x')[0]
            print("Found survivor perk - " + survivor_perk_string)
            output_to_file("Found surivor perk: {}".format(survivor_perk_string), packet_str)

        return True
    return False


def check_for_killer_perk(packet_str):
    k_perks = [m.start() for m in re.finditer('killerperk', packet_str)]

    if len(k_perks) > 0:
        for k_perk_pos in k_perks:
            killer_perk_string = packet_str[k_perk_pos:].split('\\x')[0]
            print("Found killer perk - " + killer_perk_string)
            output_to_file("Found killer perk: {}".format(killer_perk_string), packet_str)

        return True
    return False


def check_for_blueprints(packet_str):
    blueprint_list = [m.start() for m in re.finditer('blueprint', packet_str)]

    if len(blueprint_list) > 0:
        for bp in blueprint_list:
            bp_string = packet_str[bp:].split('\\x')[0]
            # if all(check_str not in packet_str for check_str in ['statuseffects', 'survivorperks', 'killerperks', 'gameplayelements']):
            if 'statuseffects' not in bp_string and 'perkconditions' not in bp_string and 'survivorperks' not in bp_string and 'killerperks' not in bp_string:
                if 'itemaddons' in bp_string:
                    print('\tFound addon: {}'.format(bp_string))
                else:
                    print("\t\t - " + bp_string)
                output_to_file("Found blueprint: {}".format(bp_string), packet_str)

        return True
    return False


def check_for_perks(packet_str):
    perk_detected = False

    for perk in killer_perks:
        if perk in packet_str:
            perk_detected = True
            print("Detected Perk: {}".format(perk))
            output_to_file("Detected Perk: {}".format(perk), packet_str)

    return perk_detected


def check_for_killer_addons(packet_str):
    killer_addon_detected = False

    for killer_addon in killer_addons:
        for addon in killer_addons[killer_addon]:
            if addon in packet_str:
                killer_addon_detected = True
                print("Detected Addon ({}): {}".format(killer_addon, addon))
                output_to_file("Detected Addon ({}): {}".format(killer_addon, addon), packet_str)

    return killer_addon_detected


def check_for_killer(packet_str):
    killer_detected = False

    for killer in killers:
        if any(substring in packet_str for substring in killers[killer]):
            killer_detected = True
            print("***Detected Killer***: {}".format(killer))
            output_to_file("Detected Killer: {}".format(killer), packet_str)

    return killer_detected


def detect_chat_message(packet_str):
    # TODO: Detect chat messages
    return False


def check_map(packet_str):
    map_detected = False

    for game_map in game_maps:
        if any(gm in packet_str for gm in game_maps[game_map]):
            map_detected = True
            print("Detected Map: {}".format(game_map))

    return map_detected


def output_to_file(s, packet_str):
    output_file.write("{}\n\t{}\n".format(s, packet_str))
    output_file.flush()


def handle_packet(packet_str):
    try:
        killer_detected = check_for_killer(packet_str=packet_str)

        perk_detected = check_for_perks(packet_str=packet_str)

        killer_addon_detected = check_for_killer_addons(packet_str=packet_str)

        killer_perk_detected = check_for_killer_perk(packet_str=packet_str)

        survivor_perk_detected = check_for_survivor_perk(packet_str=packet_str)

        extra_detected = check_for_blueprints(packet_str=packet_str)

        map_detected = check_map(packet_str=packet_str)
    except Exception as ex:
        print(ex)


class Sniffer(Thread):
    ip_killer_detected = {}
    last_killer_ip = '0'

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

        # packet_log.append(packet)

        # for p in packet_log:
        if UDP in packet:
            dport = ip_layer.payload.dport
            sport = ip_layer.payload.sport

            port_min = 40000
            port_max = 65535

            if port_max > dport > port_min or port_max > sport > port_min:
                packet_str = str(packet).lower()
                handle_packet(packet_str)


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

        output_file.close()

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
            self.root.update()

    def quit(self):
        self.t1.join(2.0)
        sys.exit(0)


# ROOT = Tk("DbD Network Sniffer", "DbD Network Sniffer", "DbD Network Sniffer")
# APP = App(ROOT)
# ROOT.mainloop()
startSniffer()
