import queue
from PIL import ImageTk, Image
from tkinter import Tk, Label, Button, messagebox, StringVar
import tkinter as tk
import os
from DBDSniffer import Killer
from DBDSniffer import Network
from DBDSniffer import QueuedOutput
from DBDSniffer import SerialThread
from DBDSniffer import Sniffer
from DBDSniffer.TkAppThreadedVars import ThreadedVars
from Utilities.configuration import config


# noinspection PyBroadException
class App(tk.Tk):
    # Class vars
    paused = False
    current_killer_portrait_path = ""
    last_current_killer_portrait_path = ""
    clear_portrait_and_perks_list = True
    current_ip = ""
    killer_ip = ""
    last_killer_ip = ""
    last_killer_ip_time = 0
    killer_ping = 999
    packet_log = []
    last_packet = ""
    substring_list = ('_leg', 'game', '_torso', '_head', 'item_', 'blueprint', 'map')

    # Setup UI vars
    default_padx = 10
    default_pady = 10
    default_image_size = (250, 250)
    killer_ip_stringvar = None
    killer_geolocation_stringvar = None
    frame_label = None
    text = None
    map_label = None
    killer_ip_label = None
    killer_geo_label = None
    pause_button_text = None
    pause_button = None
    perk_list_frame = None
    perk_list = None
    temp_image = None
    killer_portrait = None

    # Singleton Variable
    __instance = None

    def __new__(cls):
        if App.__instance is None:
            App.__instance = object.__new__(cls)
        return App.__instance

    def __init__(self):
        tk.Tk.__init__(self)

        # Set the title of the screen
        self.winfo_toplevel().title("DbD Sniffer")

        # Base Geometry setup
        default_geometry = (923, 510)
        self.geometry("{}x{}".format(default_geometry[0], default_geometry[1]))
        self.configure(background='grey')
        self.resizable(False, False)

        # Setup the UI elements
        self.ui_setup()

        # Bind window events
        self.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.bind("<Configure>", self.resizer)

        # Start sniffer
        self.queue = QueuedOutput().console_queue
        self.thread = SerialThread.SerialThread(self.queue)
        self.thread.start()
        self.process_sniffed_data()

    def ui_setup(self):
        self.killer_ip_stringvar = StringVar()
        self.killer_ip_stringvar.set("Killer IP: Not Connected")

        self.killer_geolocation_stringvar = StringVar()
        self.killer_geolocation_stringvar.set("Not Connected")

        # Handle top frame
        self.frame_label = tk.Frame(self, padx=self.default_padx, pady=self.default_pady)
        self.text = tk.Text(self, wrap='word', font='arial 11')
        self.text.grid(rowspan=2, column=0, padx=self.default_padx, pady=self.default_pady,
                       sticky=tk.N + tk.S + tk.E + tk.W)

        # Handle killer photo
        self.set_killer_portrait(self.get_temp_image_path())

        # Make map label
        self.map_label = tk.Label(self, text="Current Map: N/A")
        self.map_label.grid(row=3, column=0, padx=self.default_padx, pady=self.default_pady, sticky=tk.W)

        # Show killer IP
        self.killer_ip_label = tk.Label(self, textvariable=self.killer_ip_stringvar)
        self.killer_ip_label.grid(row=3, column=1, padx=self.default_padx, pady=self.default_pady, sticky=tk.W)

        self.killer_geo_label = tk.Label(self, textvariable=self.killer_geolocation_stringvar)
        self.killer_geo_label.grid(row=4, column=1, padx=self.default_padx, pady=self.default_pady, sticky=tk.W)

        # Add pause button
        self.pause_button_text = tk.StringVar()
        self.pause_button = tk.Button(self, textvariable=self.pause_button_text, command=self.pause_action)
        self.pause_button.grid(row=4, column=0, padx=self.default_padx, pady=self.default_pady, sticky=tk.W)
        self.pause_button_text.set("Pause")

        # Make perks list
        self.perk_list_frame = tk.Frame(self, height=130, width=self.default_image_size[1])
        self.perk_list_frame.grid(row=1, column=1)
        self.perk_list_frame.grid_propagate(False)

        self.perk_list = tk.Text(self.perk_list_frame, font='arial 10')
        self.perk_list.grid(sticky=tk.E + tk.W)

    @staticmethod
    def get_temp_image_path():
        portrait_path = config.get('dbd', 'character_portrait_path')
        temp_image_name = config.get('ui', 'placeholder_image')
        temp_image_path = "{portrait_path}{separator}{killer_portrait}".format(
            portrait_path=portrait_path,
            separator=os.sep,
            killer_portrait=temp_image_name
        )

        return temp_image_path

    def pause_action(self):
        self.paused = not self.paused

        if self.paused:
            print("Pausing!")
            self.pause_button_text.set("Unpause")
        else:
            print("Unpausing!")
            self.pause_button_text.set("Pause")

    def set_killer_portrait(self, image_path):
        # Open and resize image
        killer_img = Image.open(image_path)
        killer_img = killer_img.resize(self.default_image_size, Image.ANTIALIAS)

        # Convert image to ImageTk
        self.temp_image = ImageTk.PhotoImage(killer_img)

        # If there is already an object update it, else make a new one
        if isinstance(self.killer_portrait, type(tk.Label)):
            self.killer_portrait.configure(image=self.temp_image)
            self.killer_portrait.image = self.temp_image
        else:
            self.killer_portrait = tk.Label(self, image=self.temp_image)
            self.killer_portrait.grid(row=0, column=1, pady=(self.default_pady, 0), sticky=tk.N+tk.S+tk.E+tk.W)

        ThreadedVars.instance().last_current_killer_portrait_path = ThreadedVars.instance().current_killer_portrait_path

    def resizer(self, event):
        # print((event.width, event.height))
        pass

    def process_sniffed_data(self):
        while self.queue.qsize():
            try:
                # self.text.delete(1.0, 'end')
                if hasattr(self, 'text'):
                    queued_string = self.queue.get()

                    # TODO: Make the perks a set queue so only the last 4 unique perks are shown
                    if "Detected Perk" in queued_string:
                        self.perk_list.insert('end', queued_string)
                        self.perk_list.see(tk.END)

                    if "Detected Map: " in queued_string:
                        self.map_label.config(text="Current Map: " + queued_string.split("Detected Map: ")[-1].rstrip())
                        self.map_label.update_idletasks()

                    if ThreadedVars.instance().clear_portrait_and_perks_list:
                        ThreadedVars.instance().clear_portrait_and_perks_list = False
                        self.map_label.config(text="Current Map: N/A")
                        self.map_label.update_idletasks()
                        self.perk_list.delete('1.0', tk.END)
                        self.set_killer_portrait(self.get_temp_image_path())
                        ThreadedVars.instance().killer_ip = "Not Connected"
                        ThreadedVars.instance().killer_ping = "N/A"
                        QueuedOutput().queue_print("-" * 50)

                    self.text.insert('end', queued_string)
                    self.text.see(tk.END)
            except queue.Empty:
                pass

        if ThreadedVars.instance().current_killer_portrait_path != ThreadedVars.instance().last_current_killer_portrait_path:
            self.set_killer_portrait(ThreadedVars.instance().current_killer_portrait_path)

        if self.last_killer_ip != ThreadedVars.instance().killer_ip:
            self.last_killer_ip = ThreadedVars.instance().killer_ip
            if self.killer_ip != "Not Connected":
                try:
                    killer_geolocation = Network.instance().get_killer_geoip(ThreadedVars.instance().killer_ip)
                except Exception:
                    killer_geolocation = "Could not determine location"
            else:
                killer_geolocation = "N/A"
            self.killer_geolocation_stringvar.set(killer_geolocation)
        self.killer_ip_stringvar.set("Killer IP: {} - {}".format(ThreadedVars.instance().killer_ip, ThreadedVars.instance().killer_ping))

        self.after(100, self.process_sniffed_data)

    def on_closing(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            Sniffer.Sniffer().sniffer_thread_quit = True
            self.destroy()
