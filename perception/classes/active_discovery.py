from os import makedirs, devnull, path, remove
from subprocess import Popen, PIPE, call
from perception.shared.functions import get_product_uuid
from perception.shared.variables import nmap_tmp_dir
from perception.classes.xml_output_parser import parse_nmap_xml, parse_openvas_xml
from perception.classes.openvas import create_port_list,\
    create_config,\
    create_target,\
    create_task,\
    modify_config, \
    get_info, \
    delete_reports,\
    delete_targets,\
    delete_task,\
    start_task,\
    check_task,\
    get_report, \
    delete_port_list,\
    delete_config
from perception.classes.network import Network
import threading
import syslog
import time

FNULL = open(devnull, 'w')

# Find nmap
p = Popen(['which', 'nmap'],
          shell=False,
          stdout=PIPE)

nmap = p.stdout.read().strip().decode("utf-8")
system_uuid = get_product_uuid()


# TODO: remove duplicate code, follow DRY
def discover_live_hosts(scan_list):
    live_host_list = list()

    for x in scan_list:

        # find valid hosts and ports
        try:

            cider = Network.check_if_valid_cider(x)
            ip_addr = Network.check_if_valid_address(x)

            if ip_addr or cider:
                addr_type = None

                if ip_addr:
                    addr_type = 'host'
                if cider:
                    addr_type = 'cider'

                nmap_scan_xml_path = nmap_ss_sv_scan(x,
                                                     None,
                                                     None,
                                                     None,
                                                     None,
                                                     addr_type)

                if nmap_scan_xml_path == 99:
                    syslog.syslog(syslog.LOG_INFO, 'RunNmap error: Could not run on %s %s' % (addr_type, x))

                else:
                    live_host_list = parse_nmap_xml(nmap_scan_xml_path)
                    remove(nmap_scan_xml_path[0])

                    return live_host_list

        except TypeError as type_e:
            syslog.syslog(syslog.LOG_INFO, 'RunOpenVas error: %s' % str(type_e))
            return 99

        if not live_host_list:
            syslog.syslog(syslog.LOG_INFO, 'RunOpenVas info: Host list is empty')
            return 99


# TODO: remove duplicate code, follow DRY
def nmap_ss_sv_scan(host, mac, mac_vendor, adjacency_switch, adjacency_int, addr_type):
    port_scan = 1
    xml_file = False

    if addr_type == 'host':
        xml_file = '%s%s.xml.%d' % (nmap_tmp_dir, host, int(time.time()))
        port_scan = call([nmap,
                          '-sS',
                          '-sV',
                          host,
                          '-Pn',
                          '--open',
                          '-oX',
                          xml_file],
                         shell=False,
                         stdout=FNULL)

    if addr_type == 'cider':
        cider = host.replace('/', '_')
        xml_file = '%s%s.xml.%d' % (nmap_tmp_dir, cider, int(time.time()))
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


class RunNmap(object):
    def __init__(self, host, mac, mac_vendor, adjacency_switch, adjacency_int):
        """Run the Nmap scanner based on the nmap configuration at the (config/nmap): mode"""

        self.host = host
        self.mac = mac
        self.mac_vendor = mac_vendor
        self.adjacency_switch = adjacency_switch
        self.adjacency_int = adjacency_int

        t = threading.Thread(target=self.run)
        t.start()

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

                nmap_scan_xml_path = nmap_ss_sv_scan(self.host,
                                                     self.mac,
                                                     self.mac_vendor,
                                                     self.adjacency_switch,
                                                     self.adjacency_int,
                                                     addr_type)

                if nmap_scan_xml_path == 99:
                    syslog.syslog(syslog.LOG_INFO, 'RunNmap error: Could not run on %s %s' % (addr_type, self.host))

                else:
                    parse_nmap_xml(nmap_scan_xml_path)
                    remove(nmap_scan_xml_path[0])

        except TypeError as type_e:
            syslog.syslog(syslog.LOG_INFO, 'RunNmap error: %s' % str(type_e))


class RunOpenVas(object):
    def __init__(self, host, openvas_user_username, openvas_user_password):
        self.host = host
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

        host_ipv4 = self.host['ipv4']
        host_ipv6 = self.host['ipv6']

        # build ports
        for port in self.host['port_list']:

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
                    while True:
                        check_task_response = check_task(task_id, self.openvas_user_username,
                                                         self.openvas_user_password)
                        if check_task_response == 'Done' or check_task_response == 'Stopped':
                            break
                        time.sleep(60)

                    # download and parse the report
                    if xml_report_id is not None:
                        get_report(xml_report_id, self.openvas_user_username, self.openvas_user_password)

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

        except Exception as openvas_e:
            syslog.syslog(syslog.LOG_INFO, 'RunOpenVas error: %s' % str(openvas_e))
