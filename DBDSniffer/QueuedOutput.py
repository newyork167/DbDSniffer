import queue


class QueuedOutput:
    console_queue = queue.Queue()
    __instance = None

    def __new__(cls):
        if QueuedOutput.__instance is None:
            QueuedOutput.__instance = object.__new__(cls)
        return QueuedOutput.__instance

    def __init__(self):
        pass

    def queue_print(self, s):
        self.console_queue.put(s.rstrip() + "\n")
        print(s)
