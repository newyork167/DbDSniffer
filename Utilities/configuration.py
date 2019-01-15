import configparser
import os

# Get the working directory to open the configuration file
working_directory = os.sep.join(os.path.realpath(__file__).split(os.sep)[:-1]) + os.sep

# Instantiate the ConfigParser object
config = configparser.ConfigParser()

# Read the config file
config.read(working_directory + "config.ini")

log_file = None


def get_working_directory():
    return working_directory


def get_root_directory():
    return os.sep.join(working_directory.split(os.sep)[:-2]) + os.sep


def get(section, option):
    return config.get(section=section, option=option)


def getboolean(section, option):
    return config.getboolean(section=section, option=option)


def getint(section, option):
    return config.getint(section=section, option=option)


def getfloat(section, option):
    return config.getfloat(section=section, option=option)


def get_wd(section, option):
    return working_directory + config.get(section=section, option=option)


def get_with_root_dir(section, option):
    return get_root_directory() + config.get(section=section, option=option)
