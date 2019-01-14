import threading
import Utilities.utilities as utilities
from DBDSniffer import QueuedOutput
from DBDSniffer import Sniffer
import time


class SerialThread(threading.Thread):
    sniffer_thread_quit = False

    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue

    def run(self):
        self.start_sniffer()

    def start_sniffer(self):
        sniffer = Sniffer.Sniffer()

        QueuedOutput().queue_print("[*] Start sniffing...")
        sniffer.start()
        sniffer.run()

        try:
            while True:
                if self.sniffer_thread_quit:
                    raise KeyboardInterrupt()
                time.sleep(2)
        except KeyboardInterrupt:
            QueuedOutput().queue_print("[*] Stop sniffing")
            sniffer.join(2.0)

            utilities.output_file.close()

            if sniffer.isAlive():
                sniffer.socket.close()
