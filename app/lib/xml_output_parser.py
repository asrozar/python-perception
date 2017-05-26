# Ideally this parser should return lists of dicts and not use the database

import xml.etree.ElementTree as ET
from sqlalchemy.exc import IntegrityError
from app.database.models import InventoryHost,\
    Vulnerability
from app import Session
import syslog
from socket import gethostbyaddr, herror


def parse_openvas_xml(openvas_xml):

    name = None
    cvss = None
    cve = None
    host = None
    threat = None
    severity = None
    family = None
    port = None
    bid = None
    xrefs = None
    tags = None
    
    # Connect to the database
    openvas_db_session = Session()
    
    #  Parse the openvas xml
    try:
        # TODO add test to see of it's a file or string
        # if it's a file
        # tree = ET.parse(openvas_xml)
        # root = tree.getroot()

        # if it's a string
        root = ET.fromstring(openvas_xml)

    except ET.ParseError:
        print('could not parse openvas xml')
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

    # parse get_reports_response
    if root.tag == 'get_reports_response':

        results = root.iter('result')

        for result in results:

            try:
                name = result.find('name').text
            except AttributeError:
                pass

            try:
                host = result.find('host').text
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
                inventory_host = openvas_db_session.query(InventoryHost).filter_by(ipv4_addr=host).first()

                #  Add the vulnerability to the database
                add_vuln = Vulnerability(name=name,
                                         cvss_score=cvss,
                                         cve_id=cve,
                                         family=family,
                                         bug_id=bid,
                                         inventory_host_id=inventory_host.id,
                                         port=port,
                                         threat_score=threat,
                                         severity_score=severity,
                                         xrefs=xrefs,
                                         tags=tags)

                #  If the OS product does not exist, add it
                try:
                    openvas_db_session.add(add_vuln)
                    openvas_db_session.commit()

                except IntegrityError:
                    openvas_db_session.rollback()
    
    openvas_db_session.close()
    return 0


def parse_nmap_xml(nmap_results):

    #  Parse the nmap xml file and build the tree
    try:
        tree = ET.parse(nmap_results[0])
        root = tree.getroot()

    except ET.ParseError:
        return 99

    host_dict_list = list()

    try:
        #  Find all the hosts in the nmap scan
        for host in root.findall('host'):

            port_dict_list = list()

            ipv4 = None
            ipv6 = None
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
            ostype = None
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
                    ostype = osclass_elm[0].get('type')
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
                        ex_info = None
                        service_product = None
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
                            product = service_info.get('product')
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
                                              'product': product,
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
                                              'product': product,
                                              'extra_info': ex_info,
                                              'svc_product': svc_product}

                            port_dict_list.append(inventory_port)

                inventory_host = {'ipv4_addr': ipv4,
                                  'ipv6_addr': ipv6,
                                  'macaddr': mac_addr,
                                  'host_type': ostype,
                                  'mac_vendor': mac_vendor,
                                  'state': state,
                                  'host_name': host_name,
                                  'product': product,
                                  'adjacency_switch': adjacency_switch,
                                  'adjacency_int': adjacency_int}

                host_dict_list.append((inventory_host, port_dict_list))

    except Exception as nmap_xml_e:
        syslog.syslog(syslog.LOG_INFO, '####  Failed to parse the Nmap XML output file %s  ####' % str(nmap_results))
        syslog.syslog(syslog.LOG_INFO, str(nmap_xml_e))

    return host_dict_list
