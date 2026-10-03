import configparser

config = configparser.ConfigParser()
config.read('../settings.cfg')

# VARIABLES
steam_path = config['settings']['steam_path']
mods_active = config['active']['mods_active']