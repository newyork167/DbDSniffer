import string


class Chat:
    start_ordinal_lower = 0x05
    start_ordinal_upper = 0x85
    ordinal_step = 0x4
    chat_map_lower = dict(zip(string.ascii_lowercase, [x for x in range(start_ordinal_lower, start_ordinal_lower + len(string.ascii_lowercase) * ordinal_step, ordinal_step)]))
    chat_map_upper = dict(zip(string.ascii_uppercase, [x for x in range(start_ordinal_upper, start_ordinal_upper + len(string.ascii_lowercase) * ordinal_step, ordinal_step)]))

    chat_map = {**chat_map_lower, **chat_map_upper}

    @staticmethod
    def detect_chat_message(packet_str):
        # TODO: Detect chat messages
        return False
