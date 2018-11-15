import json
import os


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
