from os import makedirs, devnull, path, remove
from subprocess import Popen, PIPE, call
from app.lib.xml_output_parser import parse_nmap_xml
from app.lib.openvas import create_targets, create_task, delete_reports, delete_targets, delete_task, start_task, check_task, get_report
from app import check_if_valid_cider, check_if_valid_address
import threading
import syslog
import time

FNULL = open(devnull, 'w')


class RunNmap(object):
    def __init__(self, tmp_dir, host, mac, mac_vendor, adjacency_switch, adjacency_int):
        """Run the Nmap scanner based on the nmap configuration at the (config/nmap): mode"""

        self.tmp_dir = tmp_dir
        self.host = host
        self.mac = mac
        self.mac_vendor = mac_vendor
        self.adjacency_switch = adjacency_switch
        self.adjacency_int = adjacency_int

        t = threading.Thread(target=self.run, args=(tmp_dir, host, mac, mac_vendor, adjacency_switch, adjacency_int))
        t.start()

    @staticmethod
    def nmap_ss_sv_scan(nmap, tmp_dir, host, mac, mac_vendor, adjacency_switch, adjacency_int, addr_type):
        port_scan = 1
        xml_file = False

        if addr_type == 'host':
            xml_file = '%s%s.xml.%d' % (tmp_dir, host, int(time.time()))
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
            xml_file = '%s%s.xml.%d' % (tmp_dir, cider, int(time.time()))
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

    def run(self, tmp_dir, host, mac, mac_vendor, adjacency_switch, adjacency_int):

        try:
            makedirs(tmp_dir)
        except OSError as os_e:
            if os_e.errno == 17 and path.isdir(tmp_dir):
                pass
            else:
                syslog.syslog(syslog.LOG_INFO, str(os_e))

        # Find nmap
        p = Popen(['which', 'nmap'],
                  shell=False,
                  stdout=PIPE)

        nmap = p.stdout.read().strip().decode("utf-8")

        # Kick off the nmap scan
        try:

            cider = check_if_valid_cider(host)
            ip_addr = check_if_valid_address(host)

            if ip_addr or cider:
                addr_type = None

                if ip_addr:
                    addr_type = 'host'
                if cider:
                    addr_type = 'cider'

                nmap_scan_xml_path = self.nmap_ss_sv_scan(nmap,
                                                          tmp_dir,
                                                          host,
                                                          mac,
                                                          mac_vendor,
                                                          adjacency_switch,
                                                          adjacency_int,
                                                          addr_type)

                if nmap_scan_xml_path == 99:
                    syslog.syslog(syslog.LOG_INFO, 'RunNmap error: Could not run on %s %s' % (addr_type, host))

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

        t = threading.Thread(target=self.run, args=(host, openvas_user_username, openvas_user_password))
        t.start()

    @staticmethod
    def scan(host, openvas_user_username, openvas_user_password):

        target_id = None
        task_id = None
        task_name = None

        if type(host) is list:
            # create the targets to scan
            target_id = create_targets('%s.%d target' % (str(host), int(time.time())),
                                       openvas_user_username,
                                       openvas_user_password,
                                       host)

            task_name = '%s.%d scan' % (str(host), int(time.time()))

        # setup the task
        if target_id is not None:
            task_id = create_task(task_name, target_id, openvas_user_username, openvas_user_password)

        # run the task
        if task_id is not None:
            xml_report_id = start_task(task_id, openvas_user_username, openvas_user_password)

            # wait until the task is done
            while True:
                check_task_response = check_task(task_id, openvas_user_username, openvas_user_password)
                if check_task_response == 'Done' or check_task_response == 'Stopped':
                    break
                time.sleep(60)

            # download and parse the report
            if xml_report_id is not None:
                get_report(xml_report_id, openvas_user_username, openvas_user_password)

            # delete the task
            if task_id is not None:
                delete_task(task_id, openvas_user_username, openvas_user_password)

            # delete the targets
            if target_id is not None:
                delete_targets(target_id, openvas_user_username, openvas_user_password)

            # delete the report
            if xml_report_id is not None:
                delete_reports(xml_report_id, openvas_user_username, openvas_user_password)

    def run(self, host, openvas_user_username, openvas_user_password):

        try:
            self.scan(host, openvas_user_username, openvas_user_password)

        except Exception as openvas_e:
            syslog.syslog(syslog.LOG_INFO, 'RunOpenVas error: %s' % str(openvas_e))
