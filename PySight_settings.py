import configparser as ConfigParser
import logging


try:
    from pymisp import PyMISP
    from pymisp import init_misp
    HAVE_PYMISP = True
except:
    HAVE_PYMISP = False


config = ConfigParser.RawConfigParser()
logger = logging.getLogger(__name__)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fileHandler = logging.FileHandler("output.log")

#init logger
logging.basicConfig(level=logging.DEBUG)
logging.getLogger("requests").setLevel(logging.WARNING)

fileHandler.setFormatter(formatter)
logger.addHandler(fileHandler)

# set config values
config.read('config.cfg')

use_threading = config.getboolean('general', 'use_threading')
time_sleep = config.getint('general', 'time_sleep')

isight_url = config.get('isight', 'isight_url')
isight_priv_key = config.get('isight', 'isight_priv_key')
isight_pub_key = config.get('isight', 'isight_pub_key')
isight_last_hours = config.getint('isight', 'last_hours')

#### MISP STUFF

misp_url = config.get('MISP', 'misp_url')
misp_key = config.get('MISP', 'misp_key')
misp_verifycert = config.getboolean('MISP', 'misp_verifycert')
PROXY_HOST = config.get('proxy', 'host')
PROXY_PORT = config.get('proxy', 'port')
PROXY_PROTOCOLL = config.get('proxy', 'protocoll')
proxy = config.get('proxy', 'full')
proxy_adress = proxy
