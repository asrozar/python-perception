# TODO: fix in 0.7 (Make this a class)

import xml.etree.ElementTree as ET
import syslog
import json
import time
import re
from socket import gethostbyaddr, herror
from perception.config import configuration as config
from perception.database.models import NmapHost, OpenVasVuln
from sql import Sql
from esearch import Elasticsearch
import active_discovery
from perception.shared.functions import get_product_uuid

system_uuid = get_product_uuid()


def parse_openvas_xml(openvas_xml, *args):

    name = None
    cvss = None
    cve = None
    threat = None
    severity = None
    family = None
    port = None
    bid = None
    xrefs = None
    tags = None

    #  Parse the openvas xml
    try:
        # TODO add test to see of it's a file or string
        # if it's a file
        # tree = ET.parse(openvas_xml)
        # root = tree.getroot()

        # if it's a string
        root = ET.fromstring(openvas_xml)

    except ET.ParseError:
        syslog.syslog(syslog.LOG_INFO, 'could not parse openvas xml')
        return 99

    # parse get_tasks_response
    if root.tag == 'get_tasks_response':

        task = root.iter('task')
        for child in task:
            status_element = child.find('status')
            status = status_element.text
            return status

    # parse create_lsc_credential_response
    if root.tag == 'create_lsc_credential_response':

        if root.attrib['status'] == '201':
            return root.attrib['id']

        if root.attrib['status'] == '400':
            return root.attrib['status_text']

    # parse get_lsc_credentials_response
    if root.tag == 'get_lsc_credentials_response':

        lsc_list = list()
        lsc_creds = root.findall('lsc_credential')

        for cred in lsc_creds:
            cred_name = cred.find('name').text
            lsc_id = cred.attrib['id']

            lsc_list.append((cred_name, lsc_id))

        return lsc_list

    # parse get_info
    if root.tag == 'get_info_response':

        if args[0] == 'nvt_oids':
            nvt_dict_list = list()
            nvt_list = list()
            family_names = list()

            for x in root.iter('nvt'):
                try:
                    nvt_family = x.find('family').text
                except AttributeError:
                    continue

                d = dict()
                oid = x.attrib['oid']
                d['family'] = nvt_family
                d['oid'] = oid
                nvt_list.append(d)

            for d in nvt_list:
                if d['family'] not in family_names:
                    family_names.append(d['family'])

            for fam in family_names:
                oid_list = list()

                for nvtd in nvt_list:
                    if nvtd['family'] == fam:
                        oid_list.append(nvtd['oid'])

                fam_d = dict()
                fam_d['family'] = fam
                fam_d['oids'] = oid_list

                nvt_dict_list.append(fam_d)

            return nvt_dict_list

    # parse get_reports_response
    if root.tag == 'get_reports_response':

        openvas_db_session = Sql.create_session()

        results = root.iter('result')
        vulnerability_list = list()
        host_list = list()

        for result in results:

            try:
                name = result.find('name').text
            except AttributeError:
                pass

            try:
                host = result.find('host').text
                if host not in host_list:
                    host_list.append(host)
            except AttributeError:
                pass

            try:
                threat = result.find('threat').text
            except AttributeError:
                pass

            try:
                severity = result.find('severity').text
            except AttributeError:
                pass

            try:
                port = result.find('port').text
            except AttributeError:
                pass

            nvt = result.iter('nvt')

            # NVT info

            for elem in nvt:

                try:
                    cvss = elem.find('cvss_base').text
                except AttributeError:
                    pass

                try:
                    cve = elem.find('cve').text
                except AttributeError:
                    pass

                try:
                    family = elem.find('family').text
                except AttributeError:
                    pass

                try:
                    bid = elem.find('bid').text
                except AttributeError:
                    pass

                try:
                    xrefs = elem.find('xref').text
                except AttributeError:
                    pass

                try:
                    tags = elem.find('tags').text
                except AttributeError:
                    pass

            if float(cvss) > 0.0:

                vulnerability = {'openvas_vuln_name': name,
                                 'openvas_vuln_cvss_score': cvss,
                                 'openvas_vuln_cve_id': cve,
                                 'openvas_vuln_family': family,
                                 'openvas_vuln_bug_id': bid,
                                 'openvas_vuln_port': port,
                                 'openvas_vuln_threat_score': threat,
                                 'openvas_vuln_severity_score': severity,
                                 'openvas_vuln_xrefs': xrefs,
                                 'openvas_vuln_tags': tags}

                vulnerability_list.append(vulnerability)

        if len(host_list) == 1:

            vuln_host = {'openvas_vuln_perception_product_uuid': system_uuid,
                         'openvas_vuln_scan_timestamp': int(time.time()),
                         'vulns': vulnerability_list}

            openvas_vuln = Sql.get_or_create(openvas_db_session,
                                                 OpenVasVuln,
                                                 ip_addr=host_list[0],
                                                 perception_product_uuid=system_uuid)

            openvas_json_data = json.dumps(vuln_host)

            Elasticsearch.add_document(config.es_host,
                                       config.es_port,
                                       config.es_index,
                                       'openvas',
                                       str(openvas_vuln.id),
                                       openvas_json_data)

            openvas_db_session.close()
            return 0

        else:
            openvas_db_session.close()
            return 99


def parse_nmap_xml(nmap_results):

    #  Parse the nmap xml file and build the tree
    try:
        tree = ET.parse(nmap_results[0])
        root = tree.getroot()

    except ET.ParseError:
        return 99

    try:
        #  Find all the hosts in the nmap scan
        nmap_db_session = Sql.create_session()
        ov_scan_pkg = list()
        cpe_list = list()
        nmap_ts = None
        mac_vendor = None

        for host in root.findall('host'):

            port_dict_list = list()
            port_list = list()

            ipv4 = None
            ipv6 = None
            ip_addr = None

            if len(nmap_results) == 5:
                mac_addr = nmap_results[1]
                mac_vendor = nmap_results[2]
                adjacency_switch = nmap_results[3]
                adjacency_int = nmap_results[4]
            else:
                mac_addr = None
                mac_vendor = None
                adjacency_switch = None
                adjacency_int = None

            os_type = None
            host_name = None
            product = None
            product_type = None
            product_vendor = None
            product_name = None
            product_version = None
            product_update = None
            product_edition = None
            product_language = None

            os_cpe = str()

            #  Get the hosts state, and find all addresses
            state = host[0].get('state')

            if state == 'up':

                addresses = host.findall('address')
                for address in addresses:

                    if address.attrib.get('addrtype') == 'ipv4':
                        ipv4 = address.attrib.get('addr')

                    if address.attrib.get('addrtype') == 'mac':
                        mac_addr = address.attrib.get('addr')
                        mac_vendor = address.attrib.get('vendor')

                    if address.attrib.get('addrtype') == 'ipv6':
                        ipv6 = address.attrib.get('addr')

                # Get the hostname
                host_info = host.find('hostnames')
                findhostname = host_info.find('hostname')
                try:
                    host_name = findhostname.get('name')
                except AttributeError:
                    pass

                # Get OS Info
                os_elm = host.find('os')
                try:
                    osmatch_elm = os_elm.find('osmatch')
                    osclass_elm = osmatch_elm.findall('osclass')
                    os_type = osclass_elm[0].get('type')
                    try:
                        os_cpe = osclass_elm[0][0].text
                    except IndexError:
                        pass
                except AttributeError:
                    pass

                # Build product info for host OS
                try:
                    os_product = os_cpe.split(':')
                except AttributeError:
                    pass
                try:
                    product_type = os_product[1].replace('/', '')
                except IndexError:
                    pass
                try:
                    product_vendor = os_product[2]
                except IndexError:
                    pass
                try:
                    product_name = os_product[3]
                except IndexError:
                    pass
                try:
                    product_version = os_product[4]
                except IndexError:
                    pass
                try:
                    product_update = os_product[5]
                except IndexError:
                    pass
                try:
                    product_edition = os_product[6]
                except IndexError:
                    pass
                try:
                    product_language = os_product[6]
                except IndexError:
                    pass

                try:
                    if host_name is None:
                        host_name = gethostbyaddr(ipv4)[0]
                except herror:
                    pass

                if os_product != ['']:

                    product = {'cpe': os_cpe,
                               'product_type': product_type,
                               'p_vendor': product_vendor,
                               'name': product_name,
                               'version': product_version,
                               'product_update': product_update,
                               'edition': product_edition,
                               'language': product_language}

                # Find all port Info
                port_info = host.findall('ports')

                for ports in port_info:

                    p = ports.findall('port')
                    for each_port in p:

                        service_name = None
                        service_product = None
                        ex_info = None
                        svc_cpe_product = None

                        svc_cpe = str()
                        svc_cpe_product_type = str()
                        svc_cpe_product_vendor = str()

                        svc_cpe_product_name = None
                        svc_cpe_product_version = None
                        svc_cpe_product_update = None
                        svc_cpe_product_edition = None
                        svc_cpe_product_language = None

                        protocol = each_port.get('protocol')
                        portid = each_port.get('portid')
                        service_info = each_port.find('service')
                        findall_cpe = service_info.findall('cpe')

                        try:
                            svc_cpe = findall_cpe[0].text
                        except IndexError:
                            pass
                        try:
                            ex_info = service_info.get('extrainfo')
                        except IndexError:
                            pass

                        try:
                            service_name = service_info.get('name')
                        except IndexError:
                            pass

                        try:
                            service_product = service_info.get('product')
                        except IndexError:
                            pass

                            #  Build product info for SVC CPE
                        try:
                            svc_cpe_product = svc_cpe.split(':')
                        except AttributeError:
                            pass

                        if svc_cpe_product == ['']:

                            inventory_port = {'protocol': protocol,
                                              'portid': portid,
                                              'name': service_name,
                                              'product': service_product,
                                              'extra_info': ex_info}

                            port_dict_list.append(inventory_port)

                        elif svc_cpe_product is not None:

                            try:
                                svc_cpe_product_type = svc_cpe_product[1].replace('/', '')
                            except IndexError:
                                pass
                            try:
                                svc_cpe_product_vendor = svc_cpe_product[2]
                            except IndexError:
                                pass
                            try:
                                svc_cpe_product_name = svc_cpe_product[3]
                            except IndexError:
                                pass
                            try:
                                svc_cpe_product_version = svc_cpe_product[4]
                            except IndexError:
                                pass
                            try:
                                svc_cpe_product_update = svc_cpe_product[5]
                            except IndexError:
                                pass
                            try:
                                svc_cpe_product_edition = svc_cpe_product[6]
                            except IndexError:
                                pass
                            try:
                                svc_cpe_product_language = svc_cpe_product[6]
                            except IndexError:
                                pass

                            if svc_cpe not in cpe_list:
                                cpe_list.append(svc_cpe)

                            svc_product = {'cpe': svc_cpe,
                                           'product_type': svc_cpe_product_type,
                                           'svc_cpe_product_vendor': svc_cpe_product_vendor,
                                           'name': svc_cpe_product_name,
                                           'version': svc_cpe_product_version,
                                           'product_update': svc_cpe_product_update,
                                           'edition': svc_cpe_product_edition,
                                           'language': svc_cpe_product_language}

                            inventory_port = {'protocol': protocol,
                                              'portid': portid,
                                              'name': service_name,
                                              'product': service_product,
                                              'extra_info': ex_info,
                                              'svc_product': svc_product}

                            port_dict = {'protocol': protocol,
                                         'portid': portid,
                                         'svc_cpe_product_name': svc_cpe_product_name,
                                         'svc_cpe_product_version': svc_cpe_product_version}

                            port_dict_list.append(inventory_port)
                            port_list.append(port_dict)

                try:

                    nmap_o = re.match(r'^cpe:/o:', product['cpe'])

                    if nmap_o:
                        cpe_list = [product['cpe']]

                    elif not nmap_o:

                        if product['cpe'] not in cpe_list:
                            cpe_list.append(product['cpe'])

                    inventory_host = {'nmap_ipv4': ipv4,
                                      'nmap_ipv6': ipv6,
                                      'nmap_mac_addr': mac_addr,
                                      'nmap_os_type': os_type,
                                      'nmap_mac_vendor': mac_vendor,
                                      'nmap_state': state,
                                      'nmap_host_name': host_name,
                                      'nmap_product': product['cpe'],
                                      'nmap_adjacency_switch': adjacency_switch,
                                      'nmap_adjacency_int': adjacency_int}

                except TypeError:

                    if 'unknown' not in cpe_list:
                        cpe_list.append('unknown')

                    inventory_host = {'nmap_ipv4': ipv4,
                                      'nmap_ipv6': ipv6,
                                      'nmap_mac_addr': mac_addr,
                                      'nmap_os_type': os_type,
                                      'nmap_mac_vendor': mac_vendor,
                                      'nmap_state': state,
                                      'nmap_host_name': host_name,
                                      'nmap_product': None,
                                      'nmap_adjacency_switch': adjacency_switch,
                                      'nmap_adjacency_int': adjacency_int}

                nmap_ts = int(time.time())

                host_dict = {'nmap_inventory_host': inventory_host,
                             'nmap_ports': port_dict_list,
                             'nmap_perception_product_uuid': system_uuid,
                             'nmap_timestamp': nmap_ts}

                host_dict_4ov = {'ipv4': ipv4,
                                 'ipv6': ipv6,
                                 'mac_vendor': mac_vendor,
                                 'port_list': port_list}

                ov_scan_pkg.append(host_dict_4ov)

                if ipv4:
                    ip_addr = ipv4

                elif ipv6:
                    ip_addr = ipv6

                if ip_addr is not None:
                    nmap_host = Sql.get_or_create(nmap_db_session,
                                                  NmapHost,
                                                  ip_addr=ip_addr,
                                                  perception_product_uuid=system_uuid)

                    nmap_json_data = json.dumps(host_dict)

                    Elasticsearch.add_document(config.es_host,
                                               config.es_port,
                                               config.es_index,
                                               'nmap',
                                               str(nmap_host.id),
                                               nmap_json_data)

                    active_discovery.BuildAsset(ip_addr, host_name, cpe_list, nmap_ts, mac_vendor)

        nmap_db_session.close()
        return ov_scan_pkg

    except Exception as nmap_xml_e:
        syslog.syslog(syslog.LOG_INFO, '####  Failed to parse the Nmap XML output file %s  ####' % str(nmap_results))
        syslog.syslog(syslog.LOG_INFO, str(nmap_xml_e))
