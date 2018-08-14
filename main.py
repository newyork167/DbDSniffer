import queue
from pathlib import Path
from queue import Queue
from PIL import ImageTk, Image
from scapy.all import *
from threading import Thread, Event
from time import sleep
import platform
from tkinter import Tk, Label, Button, messagebox
import tkinter as tk
import threading
import sys
import re
import string
import configuration as config

console_queue = queue.Queue()
perk_queue = queue.Queue()

sniffer_thread_quit = False
current_killer_portrait_path = ""
last_current_killer_portrait_path = ""
clear_portrait_and_perks_list = False

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


class Killer:
    Huntress = "Huntress"
    Cannibal = "Cannibal"
    Hillbilly = "Hillbilly"
    Doctor = "Doctor"
    Pig = "Pig"
    Clown = "Clown"
    Hag = "Hag"
    MM = "Michael Myers"
    Nurse = "Nurse"
    SD = "Freddy Kreuger"
    Trapper = "Trapper"
    Wraith = "Wraith"


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
    Killer.Huntress: ['be_body', 'be_mask', 'be_w0', 'bear_outfit'],
    Killer.Cannibal: ['ca_body', 'ca_head0'],
    Killer.Hillbilly: ['crooked_body', 'crooked_legs', 'hb_legs', 'hb_torso', 'tc_body', 'tc_w0', 'hillbilly_'],
    Killer.Doctor: ['do_body', 'do_head', 'do_torso', 'killer07_', 'chuckles_', 'dow0', 'do_w0', 'do_weapon'],
    Killer.Pig: ['fk_body', 'fk_mask', 'fk_w0'],
    Killer.Clown: ['gk_body', 'gk_head', 'gk_w0'],
    Killer.Hag: ['ha_body', 'ha_claw', 'ha_head', 'wi_body', 'witch_outfit', 'wi_hair', 'wi_w0'],
    Killer.MM: ['mm_head0'],
    Killer.Nurse: ['nr_body', 'nr_head', 'nurse_body', 'nurse_head', 'nurse_weapon', 'nurse_outfit', 'smile', 'tn_body', 'tn_head', 'tn_w0'],
    Killer.SD: ['sd_body', 'sd_head', 'sd_w0'],
    Killer.Trapper: ['tr_body', 'tr_head', 'trapper_body', 'trapper_head', 'trw0', 'tr_mask', 's01_body', 's01_head', 's01_weapon'],
    Killer.Wraith: ['tw_head', 'wr_body', 'wr_head', 'wraith_body', 'wraith_body', 'bob_outfit'],
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
    Killer.Clown: ['bottleofcholororm', 'cheapginbottle', 'cigarbox', 'ether5', 'ether10', 'ether15', 'fingerlessparadegloves', 'flaskofbleach',
              'garishmakeupkit', 'kerosenecan', 'redheadspinkyfinger', 'robinfeather', 'smellyinnersoles', 'solventjug', 'starlingfeather',
              'stickysodabottle', 'sulfuricacidvial', 'tattoosmiddlefinger', 'thickcorkstopper', 'vhsporn',
              ],
    Killer.Nurse: ['badmankeepsake', 'badmanslastbreath', 'campbellslastbreath', 'catatonictreasure', 'darkcincture',
              'dullbracelet', 'fragilewheeze', 'ataxicrespiration', 'anxiousgasp', 'heavypanting', 'jennerslastbreath', 'kavanaghslastbreath',
              'matchbox', 'metalspoon', 'plaidflannel', 'pocketwatch', 'spasmodicbreath', 'tornbookmark', 'whitenitcomb', 'woodenhorse'
              ],

    Killer.Wraith: ['bloodblindwarrior', 'bloodblink', 'krafabai', 'windstorm', 'boneclapper', 'coxcombedclapper', 'mudallseeing',
               'mudbaikrakaeug', 'mudkrafabai', 'mudswifthunt', 'mudwindstorm', 'sootbaikrakaeug', 'sootkratin',
               'sootkuntintakkho', 'spiritallseeing', 'spiritblindwarrior', 'whiteallseeing', 'whiteblindwarrior', 'whitekuntintakkho'
               'whitetheghost', 'whitewindstorm'
               ],

    Killer.Trapper: ['bloodycoil', 'diamondstone', 'honingstone', 'logwooddye', 'oilycoil', 'paddedjaws', 'rustedjaws',
                'secondarycoil', 'serratedjaws', 'settingtools', 'stitchedbag', 'tapsetters', 'trapsetters',
                'tarbottle', 'trapperbag', 'trappergloves', 'trappersack', 'waxbrick'
                ],

    Killer.Cannibal: ['carburetortuningguide', 'chainsawfile', 'chainsbloody', 'chainsgrisly', 'chainsrusted', 'depthgaugerake',
                             'homemademuffler', 'lightchassis', 'longguidebar', 'primerbulb', 'shoplubricant', 'sparkplug', 'speedlimiter',
                             'vegetableoil', 'awardwinningchili', 'chili', 'knifescratches', 'thebeastsmark', 'thegrease'
                             ],

    Killer.Hillbilly: ['deathengravings', 'doomengravings', 'spikedboots', 'thethompsonsmix', 'thompsonsmoonshine', 'primerbulb'],

    Killer.MM: ['blondehair', 'boyfriendsmemo', 'deadrabbit', 'glassfragment', 'hairbow', 'hairbrush', 'jewelry',
                       'jewelerybox', 'jmyersmemorial', 'judithsjournal', 'judithstombstone', 'lockofhair', 'memorialflower',
                       'mirrorshard', 'reflectivefragment', 'scratchedmirror', 'tackyearrings', 'tombstonepiece', 'tuftofhair', 'vanitymirror'
                       ],

    Killer.Hag: ['bloodiedmud', 'bloddiedwater', 'bogwater', 'crackedturtleegg', 'cypressnecklet', 'deadflymud', 'disfiguredear', 'dragonflywings',
            'driedcicada', 'granmasheart', 'halfeggshell', 'mintrag', 'powderedeggshell', 'pussywillowcatkins', 'ropenecklet', 'rustyshackles',
            'scarredhand', 'swamporchidnecklace', 'waterloggedshoe', 'willowwreath'
            ],

    Killer.Doctor: ['calmcartersnotes', 'calmclass', 'diciplinecartersnotes', 'diciplineclass', 'diciplineclass', 'highstimuluselectrode', 'interviewtape',
               'iridescentking', 'mapleknight', 'moldyelectrode', 'obediencecartersnotes', 'ordercartersnotes', 'orderclass', 'polishedelectrode',
               'restraintcartersnotes', 'restraintclass', 'scrappedtape', 'cartersnotes'
               ],

    Killer.Huntress: ['amanitatoxin', 'bandagedhaft', 'begrimedhead', 'berustoxin', 'coarsestone', 'deerskingloves', 'finestone', 'flowbabushka',
                 'glowingconcoction', 'infantrybelt', 'iridescenthead', 'leatherloop', 'mannagrassbraid', 'oakhaft', 'pungentfiale', 'rustyhead',
                 'shinypin', 'venomousconcoction', 'yewseedbrew', 'yewseedconcoction',
                 ],

    Killer.SD: ['blackbox', 'bluedress', 'catblock', 'classphoto', 'gardenrake', 'greendress', 'jumprope', 'kidsdrawing',
                       'nancysmasterpiece', 'nancyssketch', 'outdoorrope', 'paintthinner', 'pillbottle', 'prototypeclaw', 'redpaintbrush', 'sheepblock',
                       'swingchains', 'unicornblock', 'woolshirt', 'zblock'
                       ],

    Killer.Pig: ['amandasletter', 'amandassecret', 'bagofgears', 'combatstraps', 'crateofgears', 'facemask', 'interlockingrazor', 'jigsawannotagedplan',
            'jigsawsketch', 'johnsmedicalfile', 'lastwill', 'razerwire', 'rulessetn2', 'rustyattachments', 'shatteredsyringe', 'slowreleasetoxin',
            'tamperedtimer', 'utilityblades', 'videotape', 'workshopgrease',
            ]
}

game_maps = {
    "Haddonfield": ['blueprints/props/05-suburbs/bp_streetpatch'],
    "Asylum": ['blueprints/props/04-asylum/bp_asy_'],
    "Red Forest": ['blueprints/props/08-boreal'],
    'Junkyard': ['blueprints/props/02-junkyard'],
    "Swamp": ['blueprints/props/06-swamp']
}

start_ordinal_lower = 0x05
start_ordinal_upper = 0x85
ordinal_step = 0x4
chat_map_lower = dict(zip(string.ascii_lowercase, [x for x in range(start_ordinal_lower, start_ordinal_lower + len(string.ascii_lowercase) * ordinal_step, ordinal_step)]))
chat_map_upper = dict(zip(string.ascii_uppercase, [x for x in range(start_ordinal_upper, start_ordinal_upper + len(string.ascii_lowercase) * ordinal_step, ordinal_step)]))

chat_map = {**chat_map_lower, **chat_map_upper}


def queue_print(s):
    console_queue.put(s.rstrip() + "\n")
    print(s)


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


def get_temp_image_path():
    portrait_path = config.get('dbd', 'character_portrait_path')
    temp_image_name = "CM_charSelect_portrait.png"
    temp_image_path = "{portrait_path}{separator}{killer_portrait}".format(
        portrait_path=portrait_path,
        separator=os.sep,
        killer_portrait=temp_image_name
    )

    return temp_image_path


def get_random_killer():
    import random

    return random.choice(list(dict(config.config.items('killer_portraits')).keys()))


def check_for_survivor_perk(packet_str):
    k_perks = [m.start() for m in re.finditer('survivorperk', packet_str)]

    if len(k_perks) > 0:
        for k_perk_pos in k_perks:
            survivor_perk_string = packet_str[k_perk_pos:].split('\\x')[0]
            queue_print("Found survivor perk - " + survivor_perk_string)
            output_to_file("Found surivor perk: {}".format(survivor_perk_string), packet_str)

        return True
    return False


def check_for_killer_perk(packet_str):
    k_perks = [m.start() for m in re.finditer('killerperk', packet_str)]

    if len(k_perks) > 0:
        for k_perk_pos in k_perks:
            killer_perk_string = packet_str[k_perk_pos:].split('\\x')[0]
            queue_print("Found killer perk - " + killer_perk_string)
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
                    queue_print('\tFound addon: {}'.format(bp_string))
                else:
                    queue_print("\t\t - " + bp_string)
                output_to_file("Found blueprint: {}".format(bp_string), packet_str)

        return True
    return False


def check_for_perks(packet_str):
    perk_detected = False

    for perk in killer_perks:
        if perk in packet_str:
            perk_detected = True
            queue_print("Detected Perk: {}".format(perk))
            output_to_file("Detected Perk: {}".format(perk), packet_str)

    return perk_detected


def check_for_killer_addons(packet_str):
    global current_killer_portrait_path

    killer_addon_detected = False

    for killer_addon in killer_addons:
        for addon in killer_addons[killer_addon]:
            if addon in packet_str:
                killer_addon_detected = True
                current_killer_portrait_path = get_killer_portrait_path(killer_addon)
                queue_print("Detected Addon ({}): {}".format(killer_addon, addon))
                output_to_file("Detected Addon ({}): {}".format(killer_addon, addon), packet_str)

    return killer_addon_detected


def check_for_killer(packet_str):
    for killer in killers:
        if any(substring in packet_str for substring in killers[killer]):
            queue_print("***Detected Killer***: {}".format(killer))
            output_to_file("Detected Killer: {}".format(killer), packet_str)
            return killer

    return ""


def detect_chat_message(packet_str):
    # TODO: Detect chat messages
    return False


def check_map(packet_str):
    map_detected = False

    for game_map in game_maps:
        if any(gm in packet_str for gm in game_maps[game_map]):
            map_detected = True
            queue_print("Detected Map: {}".format(game_map))

    return map_detected


def detect_lobby_finished(packet_str):
    return "\\xbe\\xef\\xfa\\xce" in packet_str


def output_to_file(s, packet_str):
    output_file.write("{}\n\t{}\n".format(s, packet_str))
    output_file.flush()


def handle_packet(packet_str):
    global current_killer_portrait_path, clear_portrait_and_perks_list

    try:
        killer_detected = check_for_killer(packet_str=packet_str)

        perk_detected = check_for_perks(packet_str=packet_str)

        killer_addon_detected = check_for_killer_addons(packet_str=packet_str)

        killer_perk_detected = check_for_killer_perk(packet_str=packet_str)

        survivor_perk_detected = check_for_survivor_perk(packet_str=packet_str)

        extra_detected = check_for_blueprints(packet_str=packet_str)

        map_detected = check_map(packet_str=packet_str)

        out_of_lobby_or_match_finished = detect_lobby_finished(packet_str=packet_str)

        if killer_detected:
            current_killer_portrait_path = get_killer_portrait_path(killer_detected)

        if out_of_lobby_or_match_finished:
            clear_portrait_and_perks_list = True
            queue_print("Left Lobby/Match")

    except Exception as ex:
        print(ex)


class Sniffer(Thread):
    ip_killer_detected = {}
    last_killer_ip = '0'

    def __init__(self, c_queue=None, interface=interfaces[0]['name']):
        super().__init__()

        if c_queue is None:
            global console_queue
            c_queue = console_queue

        self.daemon = True
        self.queue = c_queue
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

    def print_packet(self, packet):
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


def start_sniffer():
    global sniffer_thread_quit
    sniffer = Sniffer()

    queue_print("[*] Start sniffing...")
    sniffer.start()

    try:
        while True:
            if sniffer_thread_quit:
                raise KeyboardInterrupt()
            sleep(2)
    except KeyboardInterrupt:
        queue_print("[*] Stop sniffing")
        sniffer.join(2.0)

        output_file.close()

        if sniffer.isAlive():
            sniffer.socket.close()


class SerialThread(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        start_sniffer()


class App(tk.Tk):
    default_padx = 10
    default_pady = 10

    default_image_size = (250, 250)

    def __init__(self):
        global console_queue
        tk.Tk.__init__(self)

        # Set the title of the screen
        self.winfo_toplevel().title("DbD Sniffer")

        # Base Geometry setup
        default_geometry = (923, 470)
        self.geometry("{}x{}".format(default_geometry[0], default_geometry[1]))
        self.configure(background='grey')
        # self.resizable(False, False)

        # Setup the UI elements
        self.ui_setup()
        # self.test_ui_setup()

        # Bind window events
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.bind("<Configure>", self.resizer)

        # Start sniffer
        self.queue = console_queue
        self.thread = SerialThread(self.queue)
        self.thread.start()
        self.process_sniffed_data()

    def ui_setup(self):
        # Handle top frame
        self.frame_label = tk.Frame(self, padx=self.default_padx, pady=self.default_pady)
        self.text = tk.Text(self, wrap='word', font='arial 11')
        self.text.grid(rowspan=2, column=0, padx=self.default_padx, pady=self.default_pady, sticky=tk.N+tk.S+tk.E+tk.W)

        # Handle killer photo
        self.set_killer_portrait(get_temp_image_path())

        # Make map label
        self.map_label = tk.Label(self, text="Current Map: N/A")
        self.map_label.grid(row=3, columnspan=3, padx=self.default_padx, pady=self.default_pady, sticky=tk.W)

        # Make perks list
        self.perk_list_frame = tk.Frame(self, height=130, width=self.default_image_size[1])
        self.perk_list_frame.grid(row=1, column=1)
        self.perk_list_frame.grid_propagate(False)

        self.perk_list = tk.Text(self.perk_list_frame, font='arial 10')
        self.perk_list.grid(sticky=tk.E+tk.W)

    def set_killer_portrait(self, image_path):
        global last_current_killer_portrait_path

        # Open and resize image
        killer_img = Image.open(image_path)
        killer_img = killer_img.resize(self.default_image_size, Image.ANTIALIAS)

        # Convert image to ImageTk
        self.temp_image = ImageTk.PhotoImage(killer_img)

        # If there is already an object update it, else make a new one
        if hasattr(self, 'killer_portrait'):
            self.killer_portrait.configure(image=self.temp_image)
            self.killer_portrait.image=self.temp_image
        else:
            self.killer_portrait = tk.Label(self, image=self.temp_image)
            self.killer_portrait.grid(row=0, column=1, pady=(self.default_pady, 0), sticky=tk.N+tk.S+tk.E+tk.W)

        last_current_killer_portrait_path = current_killer_portrait_path

    def test_ui_setup(self):
        # create all of the main containers
        top_frame = tk.Frame(self, bg='cyan', width=450, height=50, pady=3)
        center = tk.Frame(self, bg='gray2', width=50, height=40, padx=3, pady=3)
        btm_frame = tk.Frame(self, bg='white', width=450, height=45, pady=3)
        btm_frame2 = tk.Frame(self, bg='lavender', width=450, height=60, pady=3)

        # layout all of the main containers
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        top_frame.grid(row=0, sticky="ew")
        center.grid(row=1, sticky="nsew")
        btm_frame.grid(row=3, sticky="ew")
        btm_frame2.grid(row=4, sticky="ew")

        # create the widgets for the top frame
        model_label = Label(top_frame, text='Model Dimensions')
        width_label = Label(top_frame, text='Width:')
        length_label = Label(top_frame, text='Length:')
        entry_W = tk.Entry(top_frame, background="pink")
        entry_L = tk.Entry(top_frame, background="orange")

        # layout the widgets in the top frame
        model_label.grid(row=0, columnspan=3)
        width_label.grid(row=1, column=0)
        length_label.grid(row=1, column=2)
        entry_W.grid(row=1, column=1)
        entry_L.grid(row=1, column=3)

        # create the center widgets
        center.grid_rowconfigure(0, weight=1)
        center.grid_columnconfigure(1, weight=1)

        ctr_left = tk.Frame(center, bg='blue', width=100, height=190)
        ctr_mid = tk.Frame(center, bg='yellow', width=250, height=190, padx=3, pady=3)
        ctr_right = tk.Frame(center, bg='green', width=100, height=190, padx=3, pady=3)

        ctr_left.grid(row=0, column=0, sticky="ns")
        ctr_mid.grid(row=0, column=1, sticky="nsew")
        ctr_right.grid(row=0, column=2, sticky="ns")

    def resizer(self, event):
        # if hasattr(self, 'text'):
        #     self.text.config(width=event.width, height=event.height)
        # print((event.width, event.height))
        pass

    def process_sniffed_data(self):
        global current_killer_portrait_path, clear_portrait_and_perks_list

        while self.queue.qsize():
            try:
                # self.text.delete(1.0, 'end')
                if hasattr(self, 'text'):
                    queued_string = self.queue.get()

                    if "Detected Perk" in queued_string:
                        self.perk_list.insert('end', queued_string)
                        self.perk_list.see(tk.END)

                    if "Detected Map: " in queued_string:
                        self.map_label.config(text="Current Map: " + queued_string.split("Detected Map: ")[-1], width=100)
                        self.map_label.update_idletasks()

                    if clear_portrait_and_perks_list:
                        clear_portrait_and_perks_list = False
                        self.map_label.config(text="Current Map: N/A")
                        self.map_label.update_idletasks()
                        self.perk_list.delete('1.0', tk.END)
                        self.set_killer_portrait(get_temp_image_path())
                        queue_print("-" * 50)

                    self.text.insert('end', queued_string)
                    self.text.see(tk.END)
            except queue.Empty:
                pass

        if current_killer_portrait_path != last_current_killer_portrait_path:
            self.set_killer_portrait(current_killer_portrait_path)

        self.after(100, self.process_sniffed_data)

    def on_closing(self):
        global sniffer_thread_quit
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            sniffer_thread_quit = True
            self.destroy()


# ROOT = Tk("DbD Network Sniffer", "DbD Network Sniffer", "DbD Network Sniffer")
app = App()
app.mainloop()
# ROOT.mainloop()
# startSniffer()
