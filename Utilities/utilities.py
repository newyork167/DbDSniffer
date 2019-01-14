import json
import os
from datetime import datetime
from Utilities import configuration as config

output_file = open('output.txt', 'w+')


class bColors:
    header = '\033[95m'

    # Underlines
    underline_red = '\033[31m'
    underline_green = '\033[32m'
    underline_yellow = '\033[33m'
    underline_blue = '\033[34m'  # Used for informational stuffz
    underline_purple = '\033[35m'
    underline_cyan = '\033[36m'
    underline_white = '\033[37m'

    green = '\033[92m' # Used for good things
    yellow = '\033[93m'
    blue = '\033[94m' # Used for informational stuffz
    purple = '\033[95m'
    cyan = '\033[96m'
    white = '\033[97m'
    red = '\033[91m' # Used for bad things

    warning = '\033[93m'

    bold = '\033[1m'
    underline = '\033[4m'

    ENDC = '\033[0m'


def create_path_if_not_exist(directory, append_separator=True):
    from pathlib import Path
    if not os.path.isabs(directory):
        path = Path(config.working_directory + directory)
    else:
        path = Path(directory)
    if not path.exists():
        path.mkdir(parents=True, exist_ok=True)
    if append_separator:
        return str(path) + os.sep
    return str(path)


def file_exists_at_path(path):
    return os.path.isfile(path)


def output_print(s, should_print=True):
    try:
        output_file_path = create_path_if_not_exist(config.get('utilities', 'output_print_file'), False)

        with open(output_file_path, 'a+') as output_file:
            output_file.write(s.strip() + '\n')
        if should_print:
            print(s)
    except Exception as ex:
        print("Utilities.output_print({args}): {ex}".format(args=s, ex=ex))


def print_color(s, color='blue', **kwargs):
    if color == 'info':
        color = 'blue'
    elif color == 'debug':
        color = 'red'
    if 'thread_name' in kwargs:
        s = "{}: {} - {}".format(datetime.now(), kwargs['thread_name'], s)
    else:
        import threading
        s = "{}: {} - {}".format(datetime.now(), threading.get_ident(), s)
    print(getattr(bColors, color.lower()) + s + bColors.ENDC)


def sanitize_file_path(path):
    path = path.replace(':', ' -')
    return "".join([c for c in path if c.isalpha() or c.isdigit() or c == ' ' or c in ('-', '.')]).rstrip()


def check_int(s):
    if s[0] in ('-', '+'):
        return s[1:].isdigit()
    return s.isdigit()


def load_json(file_path, pretty_write=False, pretty_out=None):
    if not os.path.exists(file_path):
        return False

    with open(file_path) as json_file:
        parsed = json.loads(''.join(json_file.readlines()))
        pretty = json.dumps(parsed, indent=4, sort_keys=True)

        if pretty_write:
            if pretty_out is None:
                pretty_out = file_path + '.pretty.json'

            with open(pretty_out, 'w+') as pretty_file:
                pretty_file.write(pretty)

    return pretty


def output_to_file(s, packet_str):
    # output_file.write("{}\n\t{}\n".format(s, packet_str))
    output_file.flush()
