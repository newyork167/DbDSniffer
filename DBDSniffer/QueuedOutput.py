import queue

from DBDSniffer.Singleton import Singleton
from Utilities.configuration import config


@Singleton
class QueuedOutput:
    console_queue = queue.Queue()

    def __init__(self):
        self.reset_output_file()

    def queue_print(self, s):
        self.console_queue.put(s.rstrip() + "\n")
        print(s)

    @staticmethod
    def output_to_file(s):
        with open(config.get('output', 'output_file'), 'a+') as output_file:
            output_file.write(str(s) + "\n")

    @staticmethod
    def reset_output_file():
        open(config.get('output', 'output_file'), 'w+').write("")
