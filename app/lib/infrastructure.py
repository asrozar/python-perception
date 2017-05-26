import datetime
from sqlalchemy.exc import IntegrityError
from app import IOS_SHOW_ARP,\
    IOS_TERMLEN0,\
    IOS_SHOW_ADJACENCY,\
    IOS_SHOW_CDP_DETAIL,\
    IOS_SHOW_CAM, \
    SHOW_OS, \
    IOS_SHOWIPINTBR, \
    IOS_RTR_SHOW_MODEL, \
    IOS_RTR_SHOW_SERIALNUM, \
    IOS_SHOW_LICS, \
    IOS_SWITCH_SHOW_MODEL, \
    IOS_SWITCH_SHOW_SERIALNUM,\
    IOS_SHOW_LOCAL_CONNECTIONS,\
    IOS_LAST_RESORT_SHOW_MODEL,\
    HASH_PROMPT,\
    GT_PROMPT, \
    SSH_NEW_KEY, \
    SSH_BAD_KEY, \
    SSH_REFUSED, \
    PASSWORD, \
    PERMISSION_DENIED, \
    SSH_OUTDATED_KEX, \
    SSH_OUTDATED_PROTOCOL, \
    config, \
    nmap_tmp_dir, \
    hostname_lookup, \
    splunk_sock,\
    Session
from app.lib.active_discovery import RunNmap
from app.database.models import RSInfrastructure,\
    RSAddr,\
    DiscoveryProtocolFinding,\
    SeedRouter, \
    DoNotSeed, \
    HostUsingSshv1, \
    HostWithBadSshKey
from subprocess import check_output, CalledProcessError
from pexpect import spawnu, exceptions, TIMEOUT
from re import search, sub
import syslog
import threading


def get_ssh_session(host, username):

    # 99 = refused or timed out
    # 98 = bad ssh key
    # 97 = using ssh v1

    ssh_session = 'ssh %s@%s' % (username, host)
    child = spawnu(ssh_session)
    s = child.expect([TIMEOUT,
                      unicode(SSH_NEW_KEY),
                      unicode(SSH_BAD_KEY),
                      unicode(SSH_REFUSED),
                      unicode(SSH_OUTDATED_KEX),
                      unicode(SSH_OUTDATED_PROTOCOL),
                      unicode(PASSWORD),
                      unicode(GT_PROMPT),
                      unicode(HASH_PROMPT)])

    if s == 0:
        # timed out
        return 99, ''

    elif s == 1:
        # need to add the key
        child.sendline('yes')
        s = child.expect([TIMEOUT,
                          unicode(SSH_REFUSED),
                          unicode(SSH_OUTDATED_KEX),
                          unicode(PASSWORD),
                          unicode(GT_PROMPT),
                          unicode(HASH_PROMPT)])
        if s == 0:
            return 99, ''
        elif s == 1:
            return 99, ''
        elif s == 2:
            # outdated kex
            ssh_session = 'ssh %s@%s -oKexAlgorithms=+diffie-hellman-group1-sha1' % (username, host)
            child = spawnu(ssh_session)
            s = child.expect([TIMEOUT,
                              unicode(SSH_BAD_KEY),
                              unicode(SSH_REFUSED),
                              unicode(SSH_OUTDATED_KEX),
                              unicode(SSH_OUTDATED_PROTOCOL),
                              unicode(PASSWORD),
                              unicode(GT_PROMPT),
                              unicode(HASH_PROMPT)])
            if s == 0:
                return 99, ''
            elif s == 1:
                return 99, ''
            elif s == 2:
                return 99, ''
            elif s == 3:
                return 99, ''
            elif s == 4:
                return 97, ''
            elif s == 5:
                child.sendline(config['svc_account_passwd'])
                s = child.expect([TIMEOUT,
                                  unicode(SSH_REFUSED),
                                  unicode(PASSWORD),
                                  unicode(PERMISSION_DENIED),
                                  unicode(GT_PROMPT),
                                  unicode(HASH_PROMPT)])
                if s == 0:
                    return 99, ''
                elif s == 1:
                    return 99, ''
                elif s == 2:
                    return 99, ''
                elif s == 3:
                    return 99, ''
                elif s == 4:
                    return child, GT_PROMPT
                elif s == 5:
                    return child, HASH_PROMPT

            elif s == 6:
                return s, GT_PROMPT
            elif s == 7:
                return s, HASH_PROMPT

        elif s == 3:
            child.sendline(config['svc_account_passwd'])
            s = child.expect([TIMEOUT,
                              unicode(SSH_REFUSED),
                              unicode(PASSWORD),
                              unicode(PERMISSION_DENIED),
                              unicode(GT_PROMPT),
                              unicode(HASH_PROMPT)])
            if s == 0:
                return 99, ''
            elif s == 1:
                return 99, ''
            elif s == 2:
                return 99, ''
            elif s == 3:
                return 99, ''
            elif s == 4:
                return child, GT_PROMPT
            elif s == 5:
                return child, HASH_PROMPT

        elif s == 4:
            return child, GT_PROMPT
        elif s == 5:
            return child, HASH_PROMPT

    elif s == 2:
        # bad key
        return 98, ''
    elif s == 3:
        # connection refused
        return 99, ''
    elif s == 4:
        # outdated kex
        ssh_session = 'ssh %s@%s -oKexAlgorithms=+diffie-hellman-group1-sha1' % (username, host)
        child = spawnu(ssh_session)
        s = child.expect([TIMEOUT,
                          unicode(SSH_NEW_KEY),
                          unicode(SSH_BAD_KEY),
                          unicode(SSH_REFUSED),
                          unicode(SSH_OUTDATED_KEX),
                          unicode(SSH_OUTDATED_PROTOCOL),
                          unicode(PASSWORD),
                          unicode(GT_PROMPT),
                          unicode(HASH_PROMPT)])
        if s == 0:
            return 99, ''
        elif s == 1:
            # need to add the key
            child.sendline('yes')
            s = child.expect([TIMEOUT,
                              unicode(SSH_REFUSED),
                              unicode(SSH_OUTDATED_KEX),
                              unicode(PASSWORD),
                              unicode(GT_PROMPT),
                              unicode(HASH_PROMPT)])
            if s == 0:
                return 99, ''
            elif s == 1:
                return 99, ''
            elif s == 2:
                # outdated kex
                ssh_session = 'ssh %s@%s -oKexAlgorithms=+diffie-hellman-group1-sha1' % (username, host)
                child = spawnu(ssh_session)
                s = child.expect([TIMEOUT,
                                  unicode(SSH_BAD_KEY),
                                  unicode(SSH_REFUSED),
                                  unicode(SSH_OUTDATED_KEX),
                                  unicode(SSH_OUTDATED_PROTOCOL),
                                  unicode(PASSWORD),
                                  unicode(GT_PROMPT),
                                  unicode(HASH_PROMPT)])
                if s == 0:
                    return 99, ''
                elif s == 1:
                    return 99, ''
                elif s == 2:
                    return 99, ''
                elif s == 3:
                    return 99, ''
                elif s == 4:
                    return 97, ''
                elif s == 5:
                    child.sendline(config['svc_account_passwd'])
                    s = child.expect([TIMEOUT,
                                      unicode(SSH_REFUSED),
                                      unicode(PASSWORD),
                                      unicode(PERMISSION_DENIED),
                                      unicode(GT_PROMPT),
                                      unicode(HASH_PROMPT)])
                    if s == 0:
                        return 99, ''
                    elif s == 1:
                        return 99, ''
                    elif s == 2:
                        return 99, ''
                    elif s == 3:
                        return 99, ''
                    elif s == 4:
                        return child, GT_PROMPT
                    elif s == 5:
                        return child, HASH_PROMPT

                elif s == 6:
                    return s, GT_PROMPT
                elif s == 7:
                    return s, HASH_PROMPT

            elif s == 3:
                child.sendline(config['svc_account_passwd'])
                s = child.expect([TIMEOUT,
                                  unicode(SSH_REFUSED),
                                  unicode(PASSWORD),
                                  unicode(PERMISSION_DENIED),
                                  unicode(GT_PROMPT),
                                  unicode(HASH_PROMPT)])
                if s == 0:
                    return 99, ''
                elif s == 1:
                    return 99, ''
                elif s == 2:
                    return 99, ''
                elif s == 3:
                    return 99, ''
                elif s == 4:
                    return child, GT_PROMPT
                elif s == 5:
                    return child, HASH_PROMPT

            elif s == 4:
                return child, GT_PROMPT
            elif s == 5:
                return child, HASH_PROMPT
        elif s == 2:
            return 99, ''
        elif s == 3:
            return 99, ''
        elif s == 4:
            return 99, ''
        elif s == 5:
            return 97, ''
        elif s == 6:
            child.sendline(config['svc_account_passwd'])
            s = child.expect([TIMEOUT,
                              unicode(SSH_REFUSED),
                              unicode(PASSWORD),
                              unicode(PERMISSION_DENIED),
                              unicode(GT_PROMPT),
                              unicode(HASH_PROMPT)])
            if s == 0:
                return 99, ''
            elif s == 1:
                return 99, ''
            elif s == 2:
                return 99, ''
            elif s == 3:
                return 99, ''
            elif s == 4:
                return child, GT_PROMPT
            elif s == 5:
                return child, HASH_PROMPT

        elif s == 6:
            return s, GT_PROMPT
        elif s == 7:
            return s, HASH_PROMPT

    elif s == 5:
        # outdated protocol
        return 97, ''

    elif s == 6:
        # using password not PKI
        child.sendline(config['svc_account_passwd'])
        s = child.expect([TIMEOUT,
                          unicode(SSH_REFUSED),
                          unicode(PASSWORD),
                          unicode(PERMISSION_DENIED),
                          unicode(GT_PROMPT),
                          unicode(HASH_PROMPT)])
        if s == 0:
            return 99, ''
        elif s == 1:
            return 99, ''
        elif s == 2:
            return 99, ''
        elif s == 3:
            return 99, ''
        elif s == 4:
            return child, GT_PROMPT
        elif s == 5:
            return child, HASH_PROMPT

    elif s == 7:
        # using PKI
        return child, GT_PROMPT
    elif s == 8:
        # using PKI
        return child, HASH_PROMPT
    else:
        return 99, ''


class InterrogateRSI(object):
    def __init__(self,
                 host_name,
                 ip_addr,
                 username,
                 svc_user_id,
                 seed=False):

        self.host_name = host_name
        self.ip_addr = ip_addr
        self.username = username
        self.svc_user_id = svc_user_id
        self.seed = seed

        t = threading.Thread(target=self.run, args=(host_name, ip_addr, username, svc_user_id, seed))
        t.start()
        #self.run(host_name,
        #         ip_addr,
        #         username,
        #         svc_user_id,
        #         seed)

    @staticmethod
    def interrogate(username, host):

        try:
            old_ios = None
            ios_ver = None
            nxos_ver = None
            os_line = None

            secondary_addrs_dict_list = list()
            local_host_dict_list = list()
            local_subnets_dict_list = list()
            mac_dict_list = list()
            discovery_dict_list = list()

            ssh_session, prompt = get_ssh_session(host, username)

            if ssh_session == 99:
                return 99

            if ssh_session == 98:
                return 98

            if ssh_session == 97:
                return 97

            ssh_session.sendline(IOS_TERMLEN0)
            ssh_session.expect([TIMEOUT, unicode(prompt)])
            ssh_session.sendline(SHOW_OS)
            ssh_session.expect([TIMEOUT, unicode(prompt)])
            os_software = ssh_session.before
            lines = os_software.split('\r\n')

            for line in lines:
                old_ios = search(r'^IOS\s+\(tm\)', line)
                ios_ver = search(r'(^Cisco\s+IOS\s+Software,)', line)
                nxos_ver = search(r'(^Cisco\s+Nexus\s+Operating)', line)

                if old_ios:
                    os_line = line
                    break

                elif ios_ver:
                    os_line = line
                    break

                elif nxos_ver:
                    os_line = line
                    break

            if ios_ver is not None or old_ios is not None and os_line is not None:

                adjacency_addrs_list = list()
                license_level = None
                system_serial_number = None
                model_number = None
                os_version = os_line.strip('\r\n')

                ssh_session.sendline(IOS_SWITCH_SHOW_SERIALNUM)
                ssh_session.expect([TIMEOUT, unicode(prompt)])
                ios_switch_sn = ssh_session.before

                ssh_session.sendline(IOS_SWITCH_SHOW_MODEL)
                ssh_session.expect([TIMEOUT, unicode(prompt)])
                ios_switch_model = ssh_session.before

                ssh_session.sendline(IOS_RTR_SHOW_SERIALNUM)
                ssh_session.expect([TIMEOUT, unicode(prompt)])
                ios_rtr_sn = ssh_session.before

                ssh_session.sendline(IOS_RTR_SHOW_MODEL)
                ssh_session.expect([TIMEOUT, unicode(prompt)])
                ios_rtr_model = ssh_session.before

                ssh_session.sendline(IOS_LAST_RESORT_SHOW_MODEL)
                ssh_session.expect([TIMEOUT, unicode(prompt)])
                ios_last_resort_model = ssh_session.before

                ssh_session.sendline(IOS_SHOW_LICS)
                ssh_session.expect([TIMEOUT, unicode(prompt)])
                ios_lics_model = ssh_session.before

                ssh_session.sendline(IOS_SHOWIPINTBR)
                ssh_session.expect([TIMEOUT, unicode(prompt)])
                secondary_addrs_buff = ssh_session.before
                sec_addr_lines = secondary_addrs_buff.split('\r\n')

                ssh_session.sendline(IOS_SHOW_ADJACENCY)
                ssh_session.expect([TIMEOUT, unicode(prompt)])
                local_hosts_buff = ssh_session.before
                local_hosts_lines = local_hosts_buff.split('\r\n')

                ssh_session.sendline(IOS_SHOW_LOCAL_CONNECTIONS)
                ssh_session.expect([TIMEOUT, unicode(prompt)])
                local_subnets_buff = ssh_session.before
                local_subnets_lines = local_subnets_buff.split('\r\n')

                ssh_session.sendline(IOS_SHOW_ARP)
                ssh_session.expect([TIMEOUT, unicode(prompt)])
                arp_buff = ssh_session.before
                arp_lines = arp_buff.split('\r\n')

                ssh_session.sendline(IOS_SHOW_CAM)
                ssh_session.expect([TIMEOUT, unicode(prompt)])
                cam_buff = ssh_session.before
                cam_lines = cam_buff.split('\r\n')

                ssh_session.sendline(IOS_SHOW_CDP_DETAIL)
                ssh_session.expect([TIMEOUT, unicode(prompt)])
                cdp_buff = ssh_session.before
                data_list = str(cdp_buff).split('-------------------------')

                ssh_session.close()
                rsi_output = '%s%s%s%s%s%s' % (ios_switch_sn,
                                               ios_switch_model,
                                               ios_rtr_sn,
                                               ios_rtr_model,
                                               ios_last_resort_model,
                                               ios_lics_model)

                rsinfo_lines = rsi_output.split('\r\n')

                for new_line in rsinfo_lines:
                    lic_level_match = search(r'^License\s+Level\s*:\s+([^\s]+)', new_line)

                    if lic_level_match:
                        license_level = lic_level_match.group(1)

                    switch_model_num_match = search(r'^Model\s+number\s*:\s+([^\s]+)', new_line)

                    if switch_model_num_match:
                        model_number = switch_model_num_match.group(1)

                    rtr_model_num_match = search(r'(^\*[0-9]+\s+)([A-Za-z0-9]+)', new_line)

                    if rtr_model_num_match:
                        model_number = rtr_model_num_match.group(2)

                    system_sn_match = search(r'^System\s+serial\s+number\s*:\s+([^\s]+)', new_line)

                    if system_sn_match:
                        system_serial_number = system_sn_match.group(1)

                    router_sn_match = search(r'(^Processor\s+board\s+ID\s+)(\S+)', new_line)

                    if router_sn_match:
                        system_serial_number = router_sn_match.group(2)

                # last resort model number search
                if model_number is None:

                    for l in rsinfo_lines:
                        ws_model_num_match = search(r'(WS-\S+)', l)

                        if ws_model_num_match:
                            model_number = ws_model_num_match.group(0)
                            break

                rsinfrastructure = {'os_version': os_version,
                                    'license_level': license_level,
                                    'system_serial_number': system_serial_number,
                                    'model_number': model_number}

                for sec_addr_line in sec_addr_lines:
                    rsaddr = search(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                    r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                    r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                    r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', sec_addr_line)
                    if rsaddr:
                        d = {'host': host,
                             'rsaddr': str(rsaddr.group(0))}

                        secondary_addrs_dict_list.append(d)

                for local_hosts_line in local_hosts_lines:
                    ip_addrs = search(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                      r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                      r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                      r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', local_hosts_line)

                    interface = search(r'(^\S+[ \t]{2,})(\S+)', local_hosts_line)

                    # mac_addrs = search(r'(([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})', local_hosts_line)

                    if interface and ip_addrs:
                        matched_line = interface.group(0).split(' ')
                        interface_adjacency = matched_line[-1]
                        adj_dict = {str(ip_addrs.group(0)): str(interface_adjacency)}
                        adjacency_addrs_list.append(adj_dict)

                for subnet_line in local_subnets_lines:
                    match = search(r'((?:[0-9]{1,3}\.){3}[0-9]{1,3}/\d+)', subnet_line)
                    direct_connect_match = search(r'(directly connected,)(\s+)(\S+)', subnet_line)

                    if match and direct_connect_match:
                        local_subnet_dict = {'subnet': match.group(0),
                                             'source_int': direct_connect_match.group(3)}

                        local_subnets_dict_list.append(local_subnet_dict)

                for arp_line in arp_lines:
                    ip_addrs = search(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                      r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                      r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                      r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', arp_line)

                    # and search each line for mac addresses
                    mac_addrs = search(r'(([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})', arp_line)

                    if ip_addrs and mac_addrs:

                        for addr in adjacency_addrs_list:
                            if ip_addrs.group(0) in addr:
                                host_dict = {'ip_addr': ip_addrs.group(0),
                                             'mac_addr': mac_addrs.group(0),
                                             'adjacency_int': addr[ip_addrs.group(0)]}
                                local_host_dict_list.append(host_dict)

                for cam_line in cam_lines:
                    mac_addrs = search(r'(([0-9A-Fa-f]{4}\.){2}[0-9A-Fa-f]{4})', cam_line)

                    if mac_addrs:
                        mac_addrs_line_split = cam_line.strip('*').split(' ')
                        mac_addrs_line_split = filter(None, mac_addrs_line_split)

                        if mac_addrs_line_split[0] == '---':
                            vlan_id = '0'
                        else:
                            vlan_id = mac_addrs_line_split[0]

                        mac_addr_dict = {'host': host,
                                         'mac_addr': mac_addrs_line_split[1],
                                         'type': mac_addrs_line_split[2],
                                         'port': mac_addrs_line_split[3].strip('\r\n'),
                                         'vlan': int(vlan_id)}
                        mac_dict_list.append(mac_addr_dict)

                for element in data_list:
                    # empty discovery list
                    discovery_list = []

                    # search for the device id
                    reg_device_id = search(r'(Device ID:.+?)\n', element)

                    try:

                        # add the device id to the list
                        discovery_list += [sub(r':\s+', ':', reg_device_id.group(0).strip())]
                    except AttributeError:
                        discovery_list.append('Device ID:')

                    # search for the ip address
                    reg_entry_addrs = search(r'\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                             r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                             r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.'
                                             r'(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', element)

                    try:

                        # add the ip  to the list
                        discovery_list.append('IP:%s' % str(reg_entry_addrs.group(0).strip('\n')))
                    except AttributeError:
                        discovery_list.append('IP:')

                    # search for the platform information
                    reg_platform = search(r'(Platform:.+?)\n', element)

                    try:

                        # parse platform info and clean it up
                        platform_line = sub(r':\s+', ':', reg_platform.group(0).strip())
                        platform_capabilities = platform_line.split(',  ')

                        # add the platform info to the list
                        discovery_list.append(platform_capabilities[0])
                        discovery_list.append(platform_capabilities[1])
                    except AttributeError:
                        discovery_list.append('Platform:')
                        discovery_list.append('Capabilities:')

                    # search for interface information
                    reg_int = search(r'(Interface:.+?)\n', element)

                    try:

                        # parse interface info and clean it up
                        int_line = sub(r':\s+', ':', reg_int.group(0).strip())
                        interface_port_id = int_line.split(',  ')

                        # add interface info to the list
                        discovery_list.append(interface_port_id[0])
                        discovery_list.append(interface_port_id[1])
                    except AttributeError:
                        discovery_list.append('Interface:')
                        discovery_list.append('Port ID (outgoing port):')

                    # search for advertisement info
                    reg_advertisment_ver = search(r'(advertisement version:.+?)\n', element)

                    try:

                        # parse advertisement info and clean it up
                        discovery_list += [sub(r':\s+', ':', reg_advertisment_ver.group(0).strip())]
                    except AttributeError:
                        discovery_list.append('advertisement version:')

                    # search for protocol information
                    reg_protocol_hello = search(r'(Protocol Hello:.+?)\n', element)

                    try:

                        # parse protocol info and clean it up
                        discovery_list += [sub(r':\s+', ':', reg_protocol_hello.group(0).strip())]
                    except AttributeError:
                        discovery_list.append('Protocol Hello:')

                    # search for vtp mgnt domain
                    reg_vtp_mgnt = search(r'(VTP Management Domain:.+?)\n', element)

                    try:

                        # parse vtp mgnt info and clean it up
                        discovery_list += [sub(r':\s+', ':', reg_vtp_mgnt.group(0).strip())]
                    except AttributeError:
                        discovery_list.append('VTP Management Domain:')

                    # search for native vlan info
                    reg_native_vlan = search(r'(Native VLAN:.+?)\n', element)

                    try:

                        # parse native vlan info and clean it up
                        discovery_list += [sub(r':\s+', ':', reg_native_vlan.group(0).strip())]
                    except AttributeError:
                        discovery_list.append('Native VLAN:')

                    # search for duplex info
                    reg_duplex = search(r'(Duplex:.+?)\n', element)

                    try:

                        # parse duplex info and clean it up
                        discovery_list += [sub(r':\s+', ':', reg_duplex.group(0).strip())]
                    except AttributeError:
                        discovery_list.append('Duplex:')

                    # search for power info
                    reg_power_drawn = search(r'(Power drawn:.+?)\n', element)

                    try:

                        # parse power info and clean it up
                        discovery_list += [sub(r':\s+', ':', reg_power_drawn.group(0).strip())]
                    except AttributeError:
                        discovery_list.append('Power drawn:')

                        # build the discovery protocol dictionary from the list
                        discovery_dictionary = dict(map(str, x.split(':')) for x in discovery_list)

                    # iterate the key, value pairs and change empty value to None
                    for k, v in discovery_dictionary.items():
                        if v is '':
                            discovery_dictionary[k] = None

                    if discovery_dictionary['Device ID'] is not None:
                        discovery_dict_list.append(discovery_dictionary)

                return rsinfrastructure, secondary_addrs_dict_list, local_host_dict_list, local_subnets_dict_list, mac_dict_list, discovery_dict_list

            if nxos_ver is not None and os_line is not None:
                syslog.syslog(syslog.LOG_INFO, 'Cisco Nexus OS is currently not supported')
                return 98

            else:
                ssh_session.close()
                syslog.syslog(syslog.LOG_INFO, 'Host %s got 99 due to else:' % host)
                return 99

        except exceptions.TIMEOUT:
            syslog.syslog(syslog.LOG_INFO, 'Host %s got 99 due timeout' % host)
            return 99

        except exceptions.EOF:
            syslog.syslog(syslog.LOG_INFO, 'Host %s got 99 due to EOF' % host)
            return 99

        except Exception as interrogation_e:
            syslog.syslog(syslog.LOG_INFO, 'Interrogation Exception for host %s: %s' % (host, str(interrogation_e)))
            return 99

    def run(self,
            host_name,
            ip_addr,
            username,
            svc_user_id,
            seed):
        
        # Connect to the database
        rsi_db_session = Session()

        interrogation = self.interrogate(username, ip_addr)

        if interrogation == 97:
            # add to HostUsingSshv1

            try:
                rsi_db_session.query(SeedRouter).filter(SeedRouter.ip_addr == ip_addr).delete()
                do_not_seed = HostUsingSshv1(ip_addr=ip_addr)
                rsi_db_session.add(do_not_seed)

                rsi_db_session.commit()

                if config['splunk_indexer']:
                    splunk_sock('VULNERABILITY: %s is currently using SSHv1' % ip_addr)

                return
            except Exception as e:
                syslog.syslog(syslog.LOG_INFO, str(e))
                rsi_db_session.rollback()
                return

        elif interrogation == 98:
            # add to HostWithBadSshKey

            try:
                rsi_db_session.query(SeedRouter).filter(SeedRouter.ip_addr == ip_addr).delete()
                do_not_seed = HostWithBadSshKey(ip_addr=ip_addr)
                rsi_db_session.add(do_not_seed)
                rsi_db_session.commit()

                if config['splunk_indexer']:
                    splunk_sock('DANGER: SSH key for %s has changed' % ip_addr)
                return
            except Exception as e:
                syslog.syslog(syslog.LOG_INFO, str(e))
                rsi_db_session.rollback()
                return

        elif interrogation == 99:
            # add to DoNotSeed

            try:
                rsi_db_session.query(SeedRouter).filter(SeedRouter.ip_addr == ip_addr).delete()
                do_not_seed = DoNotSeed(ip_addr=ip_addr)
                rsi_db_session.add(do_not_seed)
                rsi_db_session.commit()

                if config['splunk_indexer']:
                    splunk_sock('INFO: Perception can not access %s' % ip_addr)
                return
            except Exception as e:
                syslog.syslog(syslog.LOG_INFO, str(e))
                rsi_db_session.rollback()
                return

        try:
            rsi_db_session.query(SeedRouter).filter(SeedRouter.ip_addr == ip_addr).delete()
            rsi_db_session.commit()
        except Exception as e:
            syslog.syslog(syslog.LOG_INFO,
                          'Infrastructure Exception caught trying to remove %s from SeedRouter' % str(ip_addr))
            syslog.syslog(syslog.LOG_INFO, str(e))
            rsi_db_session.rollback()
            return

        rsinfrastructure_dict = interrogation[0]
        secondary_addrs_dicst_list = interrogation[1]
        local_host_dict_list = interrogation[2]
        local_subnets_dict_list = interrogation[3]
        mac_dict_list = interrogation[4]
        discovery_dict_list = interrogation[5]

        rsi = RSInfrastructure(ip_addr=ip_addr,
                               host_name=host_name,
                               svc_user_id=svc_user_id,
                               os_version=rsinfrastructure_dict['os_version'],
                               license_level=rsinfrastructure_dict['license_level'],
                               system_serial_number=rsinfrastructure_dict['system_serial_number'],
                               model_number=rsinfrastructure_dict['model_number'],
                               last_investigation=datetime.datetime.now())

        rsi_d = {'ip_addr': ip_addr,
                 'host_name': str(host_name),
                 'svc_user_id': str(username),
                 'os_version': str(rsinfrastructure_dict['os_version']),
                 'license_level': str(rsinfrastructure_dict['license_level']),
                 'system_serial_number': str(rsinfrastructure_dict['system_serial_number']),
                 'model_number': str(rsinfrastructure_dict['model_number'])}
        try:
            rsi_db_session.add(rsi)
            rsi_db_session.commit()

            if config['splunk_indexer']:
                splunk_sock('RSInfrastructure=%s' % rsi_d)

        except IntegrityError:
            rsi_db_session.rollback()
            rsi_db_session.query(RSInfrastructure).filter(RSInfrastructure.ip_addr == ip_addr).\
                update({'ip_addr': ip_addr,
                        'host_name': host_name,
                        'svc_user_id': svc_user_id,
                        'os_version': rsinfrastructure_dict['os_version'],
                        'license_level': rsinfrastructure_dict['license_level'],
                        'system_serial_number': rsinfrastructure_dict['system_serial_number'],
                        'model_number': rsinfrastructure_dict['model_number']})
            rsi_db_session.commit()
            rsi = rsi_db_session.query(RSInfrastructure).filter(RSInfrastructure.ip_addr == ip_addr).first()

            if config['splunk_indexer']:
                splunk_sock('RSInfrastructure=%s' % rsi_d)

        if seed is False:
            # delete rsaddrs per rsi_id
            rsi_db_session.query(RSAddr) \
                .filter(RSAddr.rsinfrastructure_id == rsi.id).delete()
            rsi_db_session.commit()

        for a in secondary_addrs_dicst_list:
            add_rsaddr = RSAddr(rsinfrastructure_id=rsi.id,
                                ip_addr=a['rsaddr'])

            rsaddr_d = {'rsinfrastructure_id': rsi.ip_addr,
                        'ip_addr': a['rsaddr']}

            rsi_db_session.add(add_rsaddr)
            rsi_db_session.commit()

            if config['splunk_indexer']:
                splunk_sock('RSAddr=%s' % rsaddr_d)

        if seed is False:
            # delete discovery_dict_list per rsi_id
            rsi_db_session.query(DiscoveryProtocolFinding) \
                .filter(DiscoveryProtocolFinding.rsinfrastructure_id == rsi.id).delete()
            rsi_db_session.commit()

        for c in discovery_dict_list:
            cdp_data = DiscoveryProtocolFinding(rsinfrastructure_id=rsi.id,
                                                remote_device_id=c['Device ID'],
                                                ip_addr=c['IP'],
                                                platform=c['Platform'],
                                                capabilities=c['Capabilities'],
                                                interface=c['Interface'],
                                                port_id=c['Port ID (outgoing port)'],
                                                discovery_version=c['advertisement version'],
                                                protocol_hello=c['Protocol Hello'],
                                                vtp_domain=c['VTP Management Domain'],
                                                native_vlan=c['Native VLAN'],
                                                duplex=c['Duplex'],
                                                power_draw=c['Power drawn'])

            cdp_data_d = {'rsinfrastructure_id': rsi.ip_addr,
                          'remote_device_id': c['Device ID'],
                          'ip_addr': c['IP'],
                          'platform': c['Platform'],
                          'capabilities': c['Capabilities'],
                          'interface': c['Interface'],
                          'port_id': c['Port ID (outgoing port)'],
                          'discovery_version': c['advertisement version'],
                          'protocol_hello': c['Protocol Hello'],
                          'vtp_domain': c['VTP Management Domain'],
                          'native_vlan': c['Native VLAN'],
                          'duplex': c['Duplex'],
                          'power_draw': c['Power drawn']}

            try:
                rsi_db_session.add(cdp_data)
                rsi_db_session.commit()
            except Exception as e:
                syslog.syslog(syslog.LOG_INFO, str(e))

            if config['splunk_indexer']:
                splunk_sock('DiscoveryProtocolFinding=%s' % cdp_data_d)

        # -------------------------------------------------------------------------------
        # The remaining data is indexed only
        # -------------------------------------------------------------------------------

        for m in mac_dict_list:

            mac_addr_table_d = {'rsinfrastructure_id': rsi.ip_addr,
                                'mac_addr': str(m['mac_addr']),
                                'type': str(m['type']),
                                'port': str(m['port']),
                                'vlan': m['vlan']}

            if config['splunk_indexer']:
                splunk_sock('MacAddrTable=%s' % mac_addr_table_d)

        for h in local_host_dict_list:

            local_host_d = {'ip_addr': str(h['ip_addr']),
                            'rsinfrastructure_id': rsi.ip_addr,
                            'mac_addr': str(h['mac_addr']),
                            'adjacency_int': str(h['adjacency_int'])}

            if config['splunk_indexer']:
                splunk_sock('LocalHost=%s' % local_host_d)

            mac_lookup_string = h['mac_addr'].replace('.', '')

            try:
                mac_vendor_lookup = check_output(['grep',
                                                  mac_lookup_string[:6].upper(),
                                                  '/usr/share/nmap/nmap-mac-prefixes'])
            except CalledProcessError:
                mac_vendor_lookup = 'Unknown MAC Vendor'

            mac_vendor = ' '.join(mac_vendor_lookup.strip().split(' ')[1:])

            if config['discovery_mode'] == 'active':
                RunNmap(nmap_tmp_dir,
                        h['ip_addr'],
                        h['mac_addr'],
                        mac_vendor,
                        '%s (%s)' % (rsi.ip_addr, rsi.host_name),
                        h['adjacency_int'])

            elif config['discovery_mode'] == 'passive':

                local_host_host_name = hostname_lookup(h['ip_addr'])

                inventory_host = {'ip_addr': str(h['ip_addr']),
                                  'macaddr': str(h['mac_addr']),
                                  'mac_vendor_id': mac_vendor,
                                  'host_name': local_host_host_name,
                                  'adjacency_switch': str('%s (%s)' % (rsi.ip_addr, rsi.host_name)),
                                  'adjacency_int': h['adjacency_int']}

                if config['splunk_indexer']:
                    splunk_sock('InventoryHost=%s' % inventory_host)

        for l in local_subnets_dict_list:

            local_subnet = {'rsinfrastructure_id': rsi.ip_addr,
                            'subnet': str(l['subnet']),
                            'source_int': str(l['source_int'])}

            if config['splunk_indexer']:
                splunk_sock('LocalSubnet=%s' % local_subnet)

        rsi_db_session.close()
        return
