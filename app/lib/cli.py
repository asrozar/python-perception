import readline
from app import db_session, nmap_tmp_dir, home_dir, splunk_sock
from subprocess import call, Popen, PIPE
from app.database.models import LocalHost,\
    OpenvasAdmin,\
    OpenvasLastUpdate,\
    SvcUser,\
    SeedRouter,\
    InventoryHost,\
    InventorySvc, \
    RSInfrastructure, \
    DiscoveryProtocolFinding,\
    LocalSubnets
from app.lib.export_reporter import ExportToXLSX
from sqlalchemy.exc import IntegrityError
from re import match
from socket import gethostbyaddr, herror

# -------------------------------------------------------------------------------
# Local Classes
# -------------------------------------------------------------------------------


class TabCompletion(object):
    def __init__(self, options):
        self.options = sorted(options)
        return

    def complete(self, text, state):
        if state == 0:
            # This is the first time for this text, so build a match list.
            if text:
                self.matches = [s
                                for s in self.options
                                if s and s.startswith(text)]
            else:
                self.matches = self.options[:]

        # Return the state'th item from the match list,
        # if we have that many.
        try:
            response = self.matches[state]
        except IndexError:
            response = None

        return response

# -------------------------------------------------------------------------------
# Helper Definitions
# -------------------------------------------------------------------------------


def get_hosts_to_scan():

    hosts = db_session.query(LocalHost).all()
    if hosts:
        hosts_to_scan = []

        for host in hosts:
            hosts_to_scan.append(host.ip_addr)

        return hosts_to_scan


def split_commands(command):
    cmd_list = list()
    cmd_list += command.split(' ')

    return cmd_list


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


# -------------------------------------------------------------------------------
# Display Definitions
# -------------------------------------------------------------------------------


def show_display(message):
    print('')
    print('%s' % message)
    print('=' * len(message))
    print('')


def print_underscore():
    print('-' * 65)


def cli_greeting(v):
    print('Welcome to Perception %s CLI, use the "?" question mark for help' % v)
    print('=================================================================')


def display_show_help():
    print('')
    print('infrastructure           Display all Route Switch Infrastructure.')
    print('firewalls                Display all Firewall Infrastructure.')
    print('local_hosts              Display all local_hosts.')
    print('local_subnets            Display all local_subnets.')
    print('inventory                Display all inventory.')
    print('seeds                    Display all seed hosts.')
    print('openvas                  Display openvas configuration.')
    print('nmap                     Display nmap configuration.')
    print('discovery                Display discovery configuration.')
    print('all                      Display all show data.')
    print_underscore()


def display_help(mode):

    if mode == '>':
        print('')
        print('config               Enter configuration mode.')
        print('show                 Display data.')
        print('run discovery        Use the local_hosts database to run network discovery.')
        print('export               Export data for reporting')
        print_underscore()

    if mode == '(config)#':
        print('')
        print('local_hosts          Configure local_hosts')
        print('nmap                 Configure Nmap options.')
        print('openvas              Configure OpenVas options.')
        print('seeds                Configure a seed router to automatically populate local_hosts.')
        print('show                 Show data.')
        print_underscore()

    if mode == '(config/local_hosts)#':
        print('')
        print('add                      Add local_hosts, Example: add 10.1.1.1 10.5.0.0/24 192.168.1.10')
        print('no                       Remove local_hosts, Example: no [ip_addr/cider]')
        print('clear local_hosts        Remove all the local_hosts, Example: clear local_hosts')
        print_underscore()

    if mode == '(config/nmap)#':
        print('')
        print('timing               Configure scan timing, Example: timing T4')
        print_underscore()

    if mode == '(config/openvas)#':
        print('')
        print('linux user           Configure linux user for authenticated scans, '
              'Example: linux user [username] [password]')
        print('smb user             Configure smb user for authenticated scans, '
              'Example: smb user [username] [password]')
        print('use local_hosts      Scan using target hosts from database, '
              'Example: use target hosts false | (Default is true)')
        print_underscore()

    if mode == '(config/seeds)#':
        print('')
        print('add              Add a seed router, Example: add [ip_addr]')
        print('no               Remove seed router, Example: no [ip_addr]')
        print_underscore()


def show_local_hosts():

    local_hosts = db_session.query(LocalHost).all()

    if local_hosts:

        if local_hosts:

            show_display('Local hosts')

            print('host\t\tmac\t\t\tswitch\t\tadjacency interface')
            print('----\t\t---\t\t\t------\t\t-------------------')
            print('')
            for t in local_hosts:
                print('%s\t%s\t%s\t%s' % (t.ip_addr, t.mac_addr, t.rsinfrastructure.ip_addr, t.adjacency_int))
            print('')
            print_underscore()


def show_local_subnets():

    local_subnets = db_session.query(LocalSubnets).all()

    if local_subnets:

        if local_subnets:

            show_display('Local subnets')

            print('subnet\t\t\t\tswitch\t\t\t\tsource interface')
            print('------\t\t\t\t------\t\t\t\t-------------------')
            print('')
            for sn in local_subnets:
                print('%s\t\t\t%s\t\t\t%s' % (sn.subnet, sn.rsinfrastructure.ip_addr, sn.source_int))
            print('')
            print_underscore()


def show_seeds():

    seed_routers = db_session.query(SeedRouter).all()

    if seed_routers:
        show_display('Showing seed routers')
        print('host\t\tname')
        print('----\t\t----')
        print('')
        for seed_router in seed_routers:
            print('%s\t%s' % (seed_router.ip_addr, seed_router.host_name))
        print_underscore()


def show_openvas():

    last_update = db_session.query(OpenvasLastUpdate).order_by(OpenvasLastUpdate.id.desc()).first()
    openvas_admin = db_session.query(OpenvasAdmin).first()

    if last_update or openvas_admin:

        if openvas_admin:
            show_display('OpenVas configuration')
            print('OpenVas username:                %s' % openvas_admin.username)
            print('OpenVas Admin Created at:        %s' % openvas_admin.created_at)
            print('OpenVas Admin Updated at:        %s' % openvas_admin.updated_at)
            print_underscore()

        if last_update:
            show_display('OpenVas last update')
            print('OpenVas last updated at:         %s' % last_update.updated_at)
            print_underscore()


def show_inventory(ip):

    inventory = None

    if ip is not None:
        inventory = db_session.query(InventoryHost).filter(InventoryHost.ip_addr == ip)

    elif ip is None:
        inventory = db_session.query(InventoryHost).all()

    if inventory:

        show_display('Inventory')
        for h in inventory:
            services = db_session.query(InventorySvc).filter(InventorySvc.inventory_host_id == h.id).all()

            if h.state == 'up':
                try:
                    print('')
                    if h.ip_addr is not None:
                        print('IP Address:                              %s' % h.ip_addr)

                    if h.macaddr is not None:
                        print('MAC Address:                             %s' % h.macaddr)

                    if h.mac_vendor is not None:
                        print('MAC Vendor Name:                         %s' % h.mac_vendor.name)

                    if h.host_type is not None:
                        print('Host Type:                               %s' % h.host_type)

                    if h.host_name is not None:
                        print('Host Name:                               %s' % h.host_name)

                    if h.local_host:
                        print('')

                        if h.local_host.rsinfrastructure.host_name:
                            print('Connected to:                            %s (%s)' % (h.local_host.rsinfrastructure.ip_addr,
                                                                                    h.local_host.rsinfrastructure.host_name))
                        else:
                            print('Connected to:                            %s' % h.local_host.rsinfrastructure.ip_addr)

                        print('Model:                                   %s' % h.local_host.rsinfrastructure.model_number)
                        print('Interface:                               %s' % h.local_host.adjacency_int)

                    if h.product is not None:
                        print('Product Name:                            %s' % h.product.name)
                        print('Product Version:                         %s' % h.product.version)

                    if h.info is not None:
                        print('Info:                                    %s' % h.info)

                    if h.comments is not None:
                        print('Comments:                                %s' % h.comments)

                    for s in services:
                        print('')
                        if s.protocol is not None:
                            print('Protocol:                                %s' % s.protocol)

                        if s.portid is not None:
                            print('Port:                                    %s' % s.portid)

                        if s.name is not None:
                            print('Name:                                    %s' % s.name)

                        if s.svc_product is not None:
                            print('Service Product:                         %s' % s.svc_product)

                        if s.extra_info is not None:
                            print('Extra Info:                              %s' % s.extra_info)

                        if s.product is not None:
                            print('Product Name:                            %s' % s.product.name)

                    print_underscore()

                except Exception as sh_e:
                    print(sh_e)


def index_inventory():

    inventory = db_session.query(InventoryHost).all()

    for h in inventory:

        d = {'ip_addr': h.ip_addr,
             'mac_addr': h.macaddr,
             'mac_vendor': str(h.mac_vendor.name),
             'hostname': str(h.host_name),
             'adjacency_switch': h.local_host.rsinfrastructure.ip_addr,
             'adjacency_int': str(h.local_host.adjacency_int)}
        splunk_sock(d)


def show_infrastructure():

    rsi = db_session.query(RSInfrastructure).all()

    if rsi:
        show_display('Route Switch Infrastructure')
        for rs in rsi:
            try:
                print('')
                print('IP Address:                           %s' % rs.ip_addr)
                try:
                    print('Host Name:                            %s' % rs.host_name)
                except AttributeError:
                    print('Host Name:                            %s' % None)

                print('Service User ID:                      %s' % rs.svc_users.username)
                print('Operating System:                     %s' % rs.os_version)
                print('License Level:                        %s' % rs.license_level)
                print('System Serial Number:                 %s' % rs.system_serial_number)
                print('System Model:                         %s' % rs.model_number)
                print_underscore()

            except Exception as rsi_e:
                print(rsi_e)


def show_discovery_protocol():

    cdp = db_session.query(DiscoveryProtocolFinding).all()

    if cdp:
        show_display('Discovery Protocol data')

        try:
            for c in cdp:
                print('')
                if c.rsinfrastructure.host_name:
                    print('Source Switch                        %s (%s)' % (c.rsinfrastructure.ip_addr,
                                                                            c.rsinfrastructure.host_name))
                else:
                    print('Source Switch                        %s' % c.rsinfrastructure.ip_addr)

                print('Remote Device                        %s' % c.remote_device_id)
                print('Remote IP Address                    %s' % c.ip_addr)
                print('Platform                             %s' % c.platform)
                print('Capabilities                         %s' % c.capabilities)
                print('Interface                            %s' % c.interface)
                print('Port ID                              %s' % c.port_id)
                print('Discovery Version                    %s' % c.discovery_version)
                print('Protocol Hello                       %s' % c.protocol_hello)
                print('VTP Domain                           %s' % c.vtp_domain)
                print('Native VLAN                          %s' % c.native_vlan)
                print('Duplex                               %s' % c.duplex)
                print('Power Draw                           %s' % c.power_draw)
                print_underscore()

        except Exception as show_cdp_e:
            print(show_cdp_e)

# -------------------------------------------------------------------------------
# Definitions to add data to the database
# -------------------------------------------------------------------------------


def clear_local_hosts():

    try:
        db_session.query(LocalHost).delete()
        db_session.commit()

    except Exception as h_e:
        db_session.rollback()
        print(h_e)

    return


def no_local_host(local_host):

    for t in local_host:
        h_id = None

        try:
            h_id = db_session.query(LocalHost).filter_by(ip_addr=t).first()

        except Exception as t_e:
            print(t_e)

        try:
            if h_id is not None:
                try:
                    db_session.query(LocalHost).filter_by(id=h_id.id).delete()
                    db_session.commit()
                except Exception as h_id_e:
                    db_session.rollback()
                    print(h_id_e)

        except Exception as error:
            print(error)


def add_local_host(hosts):

    ip_list = list()
    subnet_list = list()

    for t in hosts:

        # is a valid ip address?
        if check_if_valid_address(t):
            ip_list.append(t)

        # is a valid ip cider?
        elif check_if_valid_cider(t):
            subnet_list.append(t)

    for h in ip_list:
        add_host = LocalHost(ip_addr=h)

        try:
            db_session.add(add_host)
            db_session.commit()

        except IntegrityError:
            db_session.rollback()
            print('%s already exists' % str(h))


def add_seeds(seed_info):

    if len(seed_info) < 2:
        print('')
        print('Not enough parameters provided')
        print('Use: add [host addr] [username]')
        print_underscore()

        return

    ipaddr = seed_info[0]
    username = seed_info[1]

    if check_if_valid_address(ipaddr):

        try:
            hostname = gethostbyaddr(ipaddr)[0]
        except herror:
            hostname = None

        add_svc_user = SvcUser(username=username,
                                 description='Seed Router Service Account')

        try:
            db_session.add(add_svc_user)
            db_session.flush()
            add_router = SeedRouter(ip_addr=ipaddr,
                                    svc_user_id=add_svc_user.id,
                                    host_name=hostname)
            db_session.add(add_router)
            db_session.commit()

        except IntegrityError:
            db_session.rollback()
            user = db_session.query(SvcUser).filter_by(username=username).first()
            add_router = SeedRouter(ip_addr=ipaddr,
                                    svc_user_id=user.id,
                                    host_name=hostname)
            db_session.add(add_router)
            db_session.commit()

        except Exception as ar_e:
            db_session.rollback()
            print(ar_e)


def no_seeds(seed_info):

    ipaddr = seed_info[0]
    seed_router = db_session.query(SeedRouter).filter_by(ip_addr=ipaddr).first()

    if seed_router is not None:
        try:
            db_session.query(SeedRouter).filter_by(ip_addr=ipaddr).delete()
            db_session.commit()
        except Exception as no_seeds_e:
            db_session.rollback()
            print(no_seeds_e)


def expert_mode():
    print('\033[93m[!] WARNING:                                     [!]\033[0m')
    print('\033[93m[!] You are entering a standard bash shell       [!]\033[0m')
    print('\033[93m[!] This is a restricted area. Most things done  [!]\033[0m')
    print('\033[93m[!] in this mode will VOID your warranty! :)     [!]\033[0m')
    print('')

    p = Popen(['which', 'bash'],
              shell=False,
              stdout=PIPE)

    bash = p.stdout.read().strip().decode("utf-8")

    return call(bash, shell=True)


# -------------------------------------------------------------------------------
# Main Function
# -------------------------------------------------------------------------------


def cli_loop(prefix, mode, v):
    cli_greeting(v)

    while True:

        try:

            # ----------------------------------------------------------------------
            # Use the tab key for completion
            # ----------------------------------------------------------------------
            readline.parse_and_bind('tab: complete')

            # ----------------------------------------------------------------------
            # Register the tab completion function for all the modes
            # ----------------------------------------------------------------------

            if mode == '>':
                readline.set_completer(TabCompletion(['config',
                                                      'show',
                                                      'run discovery',
                                                      'infrastructure',
                                                      'firewalls',
                                                      'local_hosts',
                                                      'local_subnets',
                                                      'inventory',
                                                      'seeds',
                                                      'openvas',
                                                      'nmap',
                                                      'discovery',
                                                      'all',
                                                      'export',
                                                      'xlsx',
                                                      'index'
                                                      ]).complete)
            elif mode == '(config)#':
                readline.set_completer(TabCompletion(['local_hosts',
                                                      'nmap',
                                                      'openvas',
                                                      'seeds',
                                                      'config',
                                                      'show']).complete)
            elif mode == '(config/local_hosts)#':
                readline.set_completer(TabCompletion(['add',
                                                      'no',
                                                      'clear local_hosts',
                                                      'config']).complete)
            elif mode == '(config/nmap)#':
                readline.set_completer(TabCompletion(['timing',
                                                      'config']).complete)

            elif mode == '(config/openvas)#':
                readline.set_completer(TabCompletion(['linux user',
                                                      'smb user',
                                                      'use target hosts',
                                                      'use target subnets',
                                                      'no',
                                                      'config']).complete)

            elif mode == '(config/seeds)#':
                readline.set_completer(TabCompletion(['add',
                                                      'no',
                                                      'config']).complete)

            # ----------------------------------------------------------------------
            # get the user input
            # ----------------------------------------------------------------------
            try:
                command = raw_input('%s%s ' % (prefix, mode))

            # maybe your using Python 3.x
            except NameError:
                command = input('%s%s ' % (prefix, mode))

            cmd = command.split()

            try:
                # ----------------------------------------------------------------------
                # enter into and exit from config mode then go back to restart the loop
                # ----------------------------------------------------------------------

                if cmd[0] == 'config':
                    mode = '(config)#'
                    continue

                elif cmd[0] == 'end':
                    mode = '>'
                    continue

                # ----------------------------------------------------------------------
                # standard (:) mode commands
                # ----------------------------------------------------------------------
                if mode == '>':
                    if cmd[0] == 'quit' or cmd[0] == 'exit':
                        exit(0)

                    if cmd[0] == '?':
                        display_help(mode)

                    # ------------------------------------------------------------------
                    # enter into advanced configuration mode (bash)
                    # ------------------------------------------------------------------
                    if cmd[0] == 'expert':

                        if cmd[1] == 'mode':
                            expert_mode()
                            continue

                    # ------------------------------------------------------------------
                    # run commands
                    # ------------------------------------------------------------------
                    # if cmd[0] == 'run':
                    #    try:
                    #        if cmd[1] == 'discovery':
                    #            try:
                    #                if cmd[2] == 'on':
                    #                    ch_1 = check_if_valid_address(cmd[3])
                    #
                    #                    if ch_1:
                    #                        # run_now = RunDiscovery(run=True, onhost=cmd[3])
                    #
                    #                        continue
                    #                    continue
                    #
                    #            except IndexError:
                    #                pass
                    #
                    #        hosts_to_scan = get_hosts_to_scan()
                    #
                    #       if hosts_to_scan:
                    #
                    #            # run_now = RunDiscovery(run=True)
                    #            continue
                    #
                    #        else:
                    #            print('You need to add local_hosts or a seed router')
                    #    except IndexError:
                    #        pass
                    #
                    # ------------------------------------------------------------------
                    # show commands
                    # ------------------------------------------------------------------
                    if cmd[0] == 'show':

                        if cmd[1] == '?':
                            display_show_help()

                        elif cmd[1] == 'local_hosts':
                            show_local_hosts()

                        elif cmd[1] == 'local_subnets':
                            show_local_subnets()

                        elif cmd[1] == 'seeds':
                            show_seeds()

                        elif cmd[1] == 'openvas':
                            show_openvas()

                        elif cmd[1] == 'inventory':

                            try:
                                if cmd[2]:
                                    ch_1 = check_if_valid_address(cmd[2])

                                    if ch_1:
                                        show_inventory(cmd[2])
                                continue

                            except IndexError:
                                pass

                            show_inventory(None)

                        elif cmd[1] == 'infrastructure':
                            show_infrastructure()

                        elif cmd[1] == 'all':
                            show_seeds()
                            show_infrastructure()
                            show_discovery_protocol()
                            show_local_hosts()
                            show_local_subnets()
                            show_inventory(None)
                            show_openvas()
                            # show_nmap()

                    # ------------------------------------------------------------------
                    # export commands [reporting]
                    # ------------------------------------------------------------------
                    if cmd[0] == 'export':

                        if cmd[1] == 'all':

                            if cmd[2] == 'xlsx':
                                ExportToXLSX(home_dir)
                                continue

                    # ------------------------------------------------------------------
                    # index commands [reporting]
                    # ------------------------------------------------------------------
                    if cmd[0] == 'index':

                        if cmd[1] == 'all':
                            index_inventory()
                            continue

                # ----------------------------------------------------------------------
                # config (config) mode commands
                # ----------------------------------------------------------------------

                if mode == '(config)#':
                    if cmd[0] == 'exit':
                        mode = '>'
                        continue

                    if cmd[0] == '?':
                        display_help(mode)
                        continue

                    # ------------------------------------------------------------------
                    # enter into sub config modes
                    # ------------------------------------------------------------------
                    if cmd[0] == 'local_hosts' \
                            or cmd[0] == 'nmap' \
                            or cmd[0] == 'openvas' \
                            or cmd[0] == 'seeds':
                        mode = '(config/%s)#' % cmd[0]
                        continue
                        # --------------------------------------------------------------

                if mode == '(config/local_hosts)#':

                    if cmd[0] == 'exit':
                        mode = '(config)#'
                        continue

                    if cmd[0] == '?':
                        display_help(mode)
                        continue

                    # ------------------------------------------------------------------
                    # add and remove local_hosts
                    # ------------------------------------------------------------------
                    if cmd[0] == 'add':
                        add_local_host(cmd[1:])

                    if cmd[0] == 'no':
                        no_local_host(cmd[1:])

                    if ' '.join(cmd) == 'clear local_hosts':
                        clear_local_hosts()

                    # ------------------------------------------------------------------

                if mode == '(config/nmap)#':

                    if cmd[0] == 'exit':
                        mode = '(config)#'
                        continue

                    if cmd[0] == '?':
                        display_help(mode)

                if mode == '(config/openvas)#':

                    if cmd[0] == 'exit':
                        mode = '(config)#'
                        continue

                    if cmd[0] == '?':
                        display_help(mode)

                if mode == '(config/seeds)#':

                    if cmd[0] == 'exit':
                        mode = '(config)#'
                        continue

                    if cmd[0] == '?':
                        display_help(mode)
                        continue

                    # add and remove seed device
                    # ------------------------------------------------------------------
                    if cmd[0] == 'add':
                        add_seeds(cmd[1:])
                        continue

                    if cmd[0] == 'no':
                        no_seeds(cmd[1:])
                        continue
                    # ------------------------------------------------------------------

                # ----------------------------------------------------------------------

            except IndexError:
                pass

        except Exception as cli_loop_e:
            print('An error has occurred: %s' % str(cli_loop_e))
            db_session.rollback()
