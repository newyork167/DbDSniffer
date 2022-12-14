import geoip2.database
from requests import get
from scapy.all import *

from DBDSniffer import QueuedOutput
from DBDSniffer.Singleton import Singleton


@Singleton
class Network:
    interfaces = []
    local_ip_address = ""
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')

    def __init__(self):
        self.interfaces = self.get_interfaces()
        self.local_ip_address = self.get_local_ip_address()

    @staticmethod
    def get_interfaces():
        os_platform = sys.platform

        if os_platform == "Darwin":
            interfaces = [{"name": "en0"}]
        elif "win" in os_platform.lower():
            interfaces = [i for i in scapy.arch.get_windows_if_list() if
                          'vmware' not in i['name'].lower() and 'NordVPN' not in i['name']]
        else:
            interfaces = [{"name": "eth0"}]

        return interfaces

    @staticmethod
    def get_local_ip_address():
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = str(s.getsockname()[0])

        QueuedOutput.instance().queue_print("Local IP detected as: {}".format(local_ip))

        return local_ip

    @staticmethod
    def get_external_ip_address():
        return get('https://api.ipify.org').text

    def get_killer_geoip(self, killer_ip):
        response = self.reader.city(killer_ip)

        return "{city}, {state}, {country}".format(
            city=response.city.name,
            state=response.subdivisions.most_specific.name,
            country=response.country.name
        )

    @staticmethod
    def detect_lobby_finished(packet_str):
        return "\\xbe\\xef\\xfa\\xce" in packet_str
