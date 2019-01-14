from DBDSniffer.Singleton import Singleton


@Singleton
class ThreadedVars:
    clear_portrait_and_perks_list = False
    killer_ip = ""
    killer_ping = -999
    killer_portrait = ""
    last_killer_portrait_path = ""

    def __init__(self):
        self.clear_portrait_and_perks_list = False
