from os import getenv
from lib.config_parser import ConfigParser
from sqlalchemy import create_engine
from sqlalchemy.engine.url import URL
from sqlalchemy.orm import sessionmaker
from socket import gethostbyaddr, herror
import splunklib.client as client

__version__ = '0.3'
__author__ = 'Avery Rozar: avery.rozar@insecure-it.com'

config_file = getenv('PERCEPTION_CONFIG')
home_dir = getenv('HOME')

if config_file is None:
    config_file = '/etc/perception/configuration.yml'

config = ConfigParser(config_file).parse()
db_config = {'drivername': config['drivername'],
             'host': config['host'],
             'database': config['database'],
             'username': config['username'],
             'password': config['password']}

# Connect to the database
engine = create_engine(URL(**db_config), pool_size=20)
Session = sessionmaker(bind=engine)
db_session = Session()

# pexpect SSH info
SSH_NEW_KEY = '.Are you sure you want to continue connecting (yes/no)?'
SSH_BAD_KEY = 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!'
SSH_REFUSED = 'Connection refused'
SSH_OUTDATED_KEX = '.no matching key exchange method found'
SSH_OUTDATED_PROTOCOL = 'Protocol major versions differ: 2 vs. 1\\r\\r\\n'
PASSWORD = '[P|p]assword'
PERMISSION_DENIED = 'Permission denied, please try again.'

# ssh prompts
GT_PROMPT = '>$'
HASH_PROMPT = '#$'

# Cisco generic commands
SHOWVER = 'show version'
SHOW_OS = 'show version | include Software'

# Cisco IOS commands
IOS_TERMLEN0 = 'terminal length 0'
IOS_SHOW_CDP_DETAIL = 'show cdp neighbors detail'
IOS_SHOW_ADJACENCY = 'show adjacency'
IOS_SHOW_LOCAL_CONNECTIONS = 'show ip route connected | in C'
IOS_SHOW_ARP = 'show arp | exclude - | exclude Incomplete'
IOS_SHOWIPINTBR = 'show ip int br | exclude unassigned'
IOS_SHOW_CAM = 'show mac address-table | exclude All'
IOS_SWITCH_SHOW_MODEL = 'show version | include Model number'
IOS_RTR_SHOW_MODEL = 'show version | include \*'
IOS_SWITCH_SHOW_SERIALNUM = 'show version | include System serial number'
IOS_RTR_SHOW_SERIALNUM = 'show version | include Processor board ID'
IOS_SHOW_LICS = 'show version | include License Level'
IOS_LAST_RESORT_SHOW_MODEL = 'show version  | include (WS)'

# Cisco ASA commands
ASA_TERMPAGER0 = 'terminal pager 0'
ASA_SHOWARP = 'show arp'
ASA_SHOW_LOCAL_CONNECTIONS = 'show route | in C'
ASA_SHOW_XLATE = 'show xlate'
ASA_SHOW_CONN = 'show conn'

tmp_dir = '/tmp/perception/'
rsinfrastructure_tmp_dir = '%srsinfrastructure/' % tmp_dir
nmap_tmp_dir = '%snmap/' % tmp_dir


def hostname_lookup(ip_addr):
    try:
        hostname = gethostbyaddr(ip_addr)[0]
    except herror:
        hostname = 'Unknown hostname'

    return hostname


def splunk_sock(event):

    s = client.connect(host=config['splunk_host'],
                       port=config['splunk_api_port'],
                       username=config['splunk_username'],
                       password=config['splunk_password'])

    index = s.indexes[config['splunk_index']]

    with index.attached_socket(sourcetype='perception_app') as sock:
        sock.send(str(event))
