from os import makedirs, devnull, path, remove
from re import match
from subprocess import Popen, PIPE, call

from app import config, splunk_sock
from app.lib.xml_output_parser import parse_nmap_xml
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
    def nmap_ss_sv_scan(nmap, tmp_dir, host, mac, mac_vendor, adjacency_switch, adjacency_int):

        xml_file = '%s/%s.xml.%d' % (tmp_dir, host, int(time.time()))

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

            ip_addr = match(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                            r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                            r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                            r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', host)

            if ip_addr:
                nmap_scan_xml_path = self.nmap_ss_sv_scan(nmap,
                                                          tmp_dir,
                                                          host,
                                                          str(mac),
                                                          mac_vendor,
                                                          str(adjacency_switch),
                                                          adjacency_int)

                if nmap_scan_xml_path == 99:
                    syslog.syslog(syslog.LOG_INFO, 'Could not parse XML for host %s' % host)

                else:
                    parsed_results = parse_nmap_xml(nmap_scan_xml_path)[0]
                    remove(nmap_scan_xml_path[0])

                    if config['splunk_indexer']:
                        splunk_sock(parsed_results)

                    return

        except TypeError as type_e:
            syslog.syslog(syslog.LOG_INFO, 'Not ready to scan host: %s' % str(type_e))
