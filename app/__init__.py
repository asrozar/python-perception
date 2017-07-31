from os import getenv
from uuid import UUID
from sqlalchemy import create_engine
from sqlalchemy.engine.url import URL
from sqlalchemy.orm import sessionmaker
from socket import gethostbyaddr, herror
from re import match
import splunklib.client as client
import syslog
import json
import httplib


# ---------------------
# get the configuration
# ---------------------
import app.config.configuration as config

db_config = {'drivername': config.db_drivername,
             'host': config.db_host,
             'database': config.database,
             'username': config.db_username,
             'password': config.db_password}

with open('/etc/product_uuid', 'r') as f:
    try:
        system_uuid = f.read().rstrip()
        UUID(system_uuid)
    except ValueError:
        syslog.syslog(syslog.LOG_INFO, 'Error: System UUID not found')
        print('Error: System UUID not found')
        exit(99)

# --------
# app info
# --------
__version__ = '0.5'
__author__ = 'Avery Rozar: avery.rozar@insecure-it.com'

# -----------------------
# Connect to the database
# -----------------------
engine = create_engine(URL(**db_config), pool_size=20)
Session = sessionmaker(bind=engine)
db_session = Session()

# ----------------
# pexpect SSH info
# ----------------
SSH_NEW_KEY = '.Are you sure you want to continue connecting (yes/no)?'
SSH_BAD_KEY = 'WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!'
SSH_REFUSED = 'Connection refused'
SSH_OUTDATED_KEX = '.no matching key exchange method found'
SSH_OUTDATED_PROTOCOL = 'Protocol major versions differ: 2 vs. 1\\r\\r\\n'
PASSWORD = '[P|p]assword'
PERMISSION_DENIED = 'Permission denied, please try again.'

# -----------
# ssh prompts
# -----------
GT_PROMPT = '>$'
HASH_PROMPT = '#$'

# ----------------------
# Cisco generic commands
# ----------------------
SHOWVER = 'show version'
SHOW_OS = 'show version | include Software'

# ------------------
# Cisco IOS commands
# ------------------
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

# ------------------
# Cisco ASA commands
# ------------------
ASA_TERMPAGER0 = 'terminal pager 0'
ASA_SHOWARP = 'show arp'
ASA_SHOW_LOCAL_CONNECTIONS = 'show route | in C'
ASA_SHOW_XLATE = 'show xlate'
ASA_SHOW_CONN = 'show conn'

# ----------------
# environment vars
# ----------------
home_dir = getenv('HOME')
tmp_dir = '/tmp/perception/'
rsinfrastructure_tmp_dir = '%srsinfrastructure/' % tmp_dir
nmap_tmp_dir = '%snmap/' % tmp_dir


def hostname_lookup(ip_addr):
    try:
        hostname = gethostbyaddr(ip_addr)[0]
    except herror:
        hostname = None

    return hostname


def es_add_document(es_host, es_port, doc_index, doc_type, doc_id, doc):

    try:
        headers = {'Accept': 'text/plain',
                   'Content-type': 'application/json'}

        conn = httplib.HTTPConnection(es_host, es_port)

        if doc_id is None:
            conn.request('POST', '/%s/%s?' % (doc_index, doc_type), headers=headers, body=doc)

        elif doc_id is not None:
            conn.request('PUT', '/%s/%s/%s?' % (doc_index, doc_type, doc_id), headers=headers, body=doc)

        resp = conn.getresponse()
        data = resp.read()

        json_resp = json.loads(data)

        if resp.status == 400:
            syslog.syslog(syslog.LOG_INFO, str(json_resp))

        elif resp.status == 403:
            syslog.syslog(syslog.LOG_INFO, str(json_resp))

        elif resp.status == 404:
            syslog.syslog(syslog.LOG_INFO, str(json_resp))

        elif resp.status == 409:
            syslog.syslog(syslog.LOG_INFO, str(json_resp))

        elif resp.status == 412:
            syslog.syslog(syslog.LOG_INFO, str(json_resp))

        elif resp.status == 500:
            syslog.syslog(syslog.LOG_INFO, str(json_resp))

        elif resp.status == 503:
            syslog.syslog(syslog.LOG_INFO, str(json_resp))

    except Exception as es_add_data_e:
        syslog.syslog(syslog.LOG_INFO, 'es_add_document error: %s' % str(es_add_data_e))
        syslog.syslog(syslog.LOG_INFO, 'es_add_document event: %s' % str(str(doc)))


def splunk_sock(event, index_name):
    try:
        s = client.connect(host=config.splunk_host,
                           port=config.splunk_api_port,
                           username=config.splunk_username,
                           password=config.splunk_password)

        index = s.indexes[index_name]

        with index.attached_socket(sourcetype='perception_app') as sock:
            sock.send(str(event))
        return 0

    except Exception as splunk_sock_e:
        syslog.syslog(syslog.LOG_INFO, 'splunk_sock error: %s' % str(splunk_sock_e))
        syslog.syslog(syslog.LOG_INFO, 'splunk_sock event: %s' % str(event))
        return 99


def check_if_valid_cider(cider):

    # is a valid ipv4 cider?
    if match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)'
             r'{3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$', cider):
        return True

    # is a valid ipv6 cider?
    if match(r'^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|'
             r'((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:)'
             r'{5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]'
             r'?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?#'
             r'((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:)'
             r'{3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)'
             r'(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|'
             r'((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|'
             r':))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|'
             r'2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|'
             r'((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|'
             r':)))(%.+)?s*(\/(d|dd|1[0-1]d|12[0-8]))$', cider):
        return True

    return False


def check_if_valid_address(ipaddr):

    # is a valid ipv4 address?
    if match(r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.)'
             r'{3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$', ipaddr):
        return True

    # is a valid ipv6 address?
    elif match(r'^s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:)'
               r'{6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:)'
               r')|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]d|1dd|[1-9]?d)'
               r'(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4})'
               r'{1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]'
               r'?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}'
               r':((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:)'
               r'{2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)'
               r'(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|'
               r'((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|'
               r':))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]d|1dd|[1-9]?d)'
               r'(.(25[0-5]|2[0-4]d|1dd|[1-9]?d)){3}))|:)))(%.+)?s*', ipaddr):
        return True

    return False


def get_or_create(session, model, **kwargs):
    instance = session.query(model).filter_by(**kwargs).first()
    if instance:
        return instance
    else:
        instance = model(**kwargs)
        session.add(instance)
        session.commit()
        return instance
