from os import makedirs, devnull, path, remove
from subprocess import Popen, PIPE, call
from perception.database.models import Asset
from perception.shared.functions import get_product_uuid
from perception.shared.variables import nmap_tmp_dir
from perception.classes.xml_parser import parse_nmap_xml, esearch, sql
from perception.classes.openvas import create_port_list,\
    create_target,\
    create_task,\
    delete_reports,\
    delete_targets,\
    delete_task,\
    start_task,\
    check_task,\
    get_report, \
    delete_port_list
from perception.classes.network import Network
from perception.config import configuration as config
import threading
import syslog
import time
import socket
import difflib
import json

FNULL = open(devnull, 'w')

# Find nmap
p = Popen(['which', 'nmap'],
          shell=False,
          stdout=PIPE)

nmap = p.stdout.read().strip().decode("utf-8")
system_uuid = get_product_uuid()


class RunNmap(object):
    def __init__(self, host, mac, mac_vendor, adjacency_switch, adjacency_int, vuln_scan, openvas_user_username, openvas_user_password):
        """Run the Nmap scanner based on the nmap configuration at the (config/nmap): mode"""

        self.host = host
        self.mac = mac
        self.mac_vendor = mac_vendor
        self.adjacency_switch = adjacency_switch
        self.adjacency_int = adjacency_int
        self.vuln_scan = vuln_scan
        self.openvas_user_username = openvas_user_username
        self.openvas_user_password = openvas_user_password

        t = threading.Thread(target=self.run)
        t.start()

    @staticmethod
    def nmap_ssa_scan(host, mac, mac_vendor, adjacency_switch, adjacency_int, addr_type):
        port_scan = 1
        xml_file = False
        nmap_ts = int(time.time())

        if addr_type == 'host':
            xml_file = '%s%s.xml.%d' % (nmap_tmp_dir, host, nmap_ts)
            port_scan = call([nmap,
                              '-sS',
                              '-A',
                              host,
                              '-Pn',
                              '--open',
                              '-oX',
                              xml_file],
                             shell=False,
                             stdout=FNULL)

        if addr_type == 'cider':
            cider = host.replace('/', '_')
            xml_file = '%s%s.xml.%d' % (nmap_tmp_dir, cider, nmap_ts)
            port_scan = call([nmap,
                              '-sS',
                              '-sV',
                              host,
                              '--open',
                              '-oX',
                              xml_file],
                             shell=False,
                             stdout=FNULL)

        if port_scan == 0:
            return xml_file, mac, mac_vendor, adjacency_switch, adjacency_int

        else:
            return 99

    def run(self):

        try:
            makedirs(nmap_tmp_dir)
        except OSError as os_e:
            if os_e.errno == 17 and path.isdir(nmap_tmp_dir):
                pass
            else:
                syslog.syslog(syslog.LOG_INFO, str(os_e))

        # Kick off the nmap scan
        try:

            cider = Network.check_if_valid_cider(self.host)
            ip_addr = Network.check_if_valid_address(self.host)

            if ip_addr or cider:
                addr_type = None

                if ip_addr:
                    addr_type = 'host'
                if cider:
                    addr_type = 'cider'

                nmap_scan_xml_path = self.nmap_ssa_scan(self.host,
                                                        self.mac,
                                                        self.mac_vendor,
                                                        self.adjacency_switch,
                                                        self.adjacency_int,
                                                        addr_type)

                if nmap_scan_xml_path == 99:
                    syslog.syslog(syslog.LOG_INFO, 'RunNmap error: Could not run on %s %s' % (addr_type, self.host))

                else:
                    scn_pkg_list, cpe_list, mac_vendor, nmap_ts = parse_nmap_xml(nmap_scan_xml_path)
                    remove(nmap_scan_xml_path[0])

                    # build asset doc for ES
                    try:
                        name = socket.gethostbyaddr(self.host)
                    except socket.herror:
                        name = ['unknown']

                    # if nmap_ts is not None:
                    BuildAsset(self.host, name[0], cpe_list, nmap_ts, mac_vendor)

                    if self.vuln_scan is True and self.openvas_user_username and self.openvas_user_password:

                        for scn_pkg in scn_pkg_list:
                            RunOpenVas(scn_pkg, self.openvas_user_username, self.openvas_user_password)

        except TypeError as type_e:
            syslog.syslog(syslog.LOG_INFO, 'RunNmap error: %s' % str(type_e))


class BuildAsset(object):
    def __init__(self, address, name, cpe_list, discovery_ts, hardware):
        self.address = address
        self.name = name
        self.cpe_list = cpe_list
        self.discovery_ts = discovery_ts
        self.hardware = hardware

        self.profiler()

        t = threading.Thread(target=self.run)
        t.start()

    def profiler(self):
        oh_list = list()
        o = 0
        h = 0

        for cpe in self.cpe_list:
            cpe_split = cpe.split(':')
            cpe_type = cpe_split[1].lstrip('/')

            if cpe_type != 'a':
                if cpe_type not in oh_list:

                    if cpe_type == 'o':
                        o += 1
                    elif cpe_type == 'h':
                        h += 1

                    oh_list.append(cpe)

        if len(oh_list) == 1:

            return oh_list[0]

        elif len(oh_list) > 1:

            if o >= 1:
                os_list = difflib.get_close_matches('cpe:/o:', oh_list)

                if os_list == 1:

                    return os_list[0]

                else:
                    syslog.syslog(syslog.LOG_INFO, 'BuildAsset info, multiple cpe options: %s' % str(oh_list))

    def run(self):
        clean_name = None
        os_cpe = self.profiler()
        os_cpe_split = os_cpe.split(':')

        try:
            product = os_cpe_split[3]

        except IndexError:
            product = None

        try:
            version = os_cpe_split[4]

        except IndexError:
            version = None

        if product is not None:
            split_prod = product.split('_')
            joined_name = ' '.join(split_prod)

            if version:
                clean_name = '%s %s' % (joined_name, version)

            elif version is None:
                clean_name = joined_name

        asset = {'address': self.address,
                 'name': self.name,
                 'os': clean_name.upper(),
                 'discovery_ts': self.discovery_ts,
                 'hardware': self.hardware}

        db_session = sql.Sql.create_session()

        assets = sql.Sql.get_or_create(db_session,
                                       Asset,
                                       ip_addr=self.address,
                                       perception_product_uuid=system_uuid)

        nmap_json_data = json.dumps(asset)

        esearch.Elasticsearch.add_document(config.es_host,
                                           config.es_port,
                                           config.es_index,
                                           'assets',
                                           str(assets.id),
                                           nmap_json_data)
        db_session.close()


class RunOpenVas(object):
    def __init__(self, scn_pkg, openvas_user_username, openvas_user_password):
        self.scn_pkg = scn_pkg
        self.openvas_user_username = openvas_user_username
        self.openvas_user_password = openvas_user_password

        t = threading.Thread(target=self.run)
        t.start()

    def scan(self):
        scan_ts = str(int(time.time()))
        udp_list = list()
        tcp_list = list()
        tcp_port_list_id = False
        udp_port_list_id = False

        host_ipv4 = self.scn_pkg['ipv4']
        host_ipv6 = self.scn_pkg['ipv6']

        # build ports
        for port in self.scn_pkg['port_list']:

            if port['protocol'] == 'tcp':
                tcp_list.append(port['portid'])

            if port['protocol'] == 'udp':
                udp_list.append(port['portid'])

        if udp_list:
            syslog.syslog(syslog.LOG_INFO, 'host %s has a udp port list of: %s' % (str(host_ipv4), str(udp_list)))

        if tcp_list:
            tcp_port_list_id = create_port_list('%s.%s tcp ports' % (str(host_ipv4), scan_ts),
                                                self.openvas_user_username,
                                                self.openvas_user_password,
                                                tcp_list,
                                                'tcp')
        if udp_list:
            udp_port_list_id = create_port_list('%s.%s udp ports' % (str(host_ipv4), scan_ts),
                                                self.openvas_user_username,
                                                self.openvas_user_password,
                                                udp_list,
                                                'udp')

        if tcp_port_list_id:
            task_id = None

            # create the targets to scan
            target_id = create_target('%s.%s target' % (str(host_ipv4), scan_ts),
                                      self.openvas_user_username,
                                      self.openvas_user_password,
                                      host_ipv4,
                                      tcp_port_list_id)

            task_name = '%s.%s scan' % (str(host_ipv4), scan_ts)

            # setup the task
            if target_id is not None:
                task_id = create_task(task_name,
                                      target_id,
                                      '698f691e-7489-11df-9d8c-002264764cea',
                                      self.openvas_user_username,
                                      self.openvas_user_password)

            # run the task
            if task_id is not None:
                xml_report_id = start_task(task_id, self.openvas_user_username, self.openvas_user_password)

                if xml_report_id:

                    # wait until the task is done

                    try:
                        while True:
                            check_task_response = check_task(task_id, self.openvas_user_username,
                                                             self.openvas_user_password)
                            if check_task_response == 'Done' or check_task_response == 'Stopped':
                                # parse the report
                                get_report(xml_report_id, self.openvas_user_username, self.openvas_user_password)
                                break

                            time.sleep(60*3)

                    except Exception as waiting_on_task:
                        syslog.syslog(syslog.LOG_INFO, 'RunOpenVas waiting_on_task error: %s' % str(waiting_on_task))

                    # delete the task
                    if task_id is not None:
                        delete_task(task_id, self.openvas_user_username, self.openvas_user_password)

                    # delete the targets
                    if target_id is not None:
                        delete_targets(target_id, self.openvas_user_username, self.openvas_user_password)

                    # delete the tcp_port_list_id
                    if tcp_port_list_id is not None:
                        delete_port_list(tcp_port_list_id, self.openvas_user_username,
                                         self.openvas_user_password)

                        # delete the udp_port_list_id
                    if udp_port_list_id is not None:
                        delete_port_list(udp_port_list_id, self.openvas_user_username,
                                         self.openvas_user_password)

                    # delete the report
                    if xml_report_id is not None:
                        delete_reports(xml_report_id, self.openvas_user_username,
                                       self.openvas_user_password)

    def run(self):

        try:

            self.scan()

        except Exception as RunOpenVas_Error:
            syslog.syslog(syslog.LOG_INFO, 'RunOpenVas error: %s' % str(RunOpenVas_Error))
