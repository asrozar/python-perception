import readline
from app import db_session, check_if_valid_address, system_uuid
from subprocess import call, Popen, PIPE
from app.database.models import OpenvasAdmin,\
    OpenvasLastUpdate,\
    SvcUser,\
    SeedRouter,\
    RSInfrastructure, \
    DiscoveryProtocolFinding
from send_message import SendToRabbitMQ
from sqlalchemy.exc import IntegrityError
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


def split_commands(command):
    cmd_list = list()
    cmd_list += command.split(' ')

    return cmd_list

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
    print('seeds                    Display all seed hosts.')
    print('openvas                  Display openvas configuration.')
    print('nmap                     Display nmap configuration.')
    print('all                      Display all show data.')
    print_underscore()


def display_help(mode):

    if mode == '>':
        print('')
        print('config               Enter configuration mode.')
        print('show                 Display data.')
        print('run                  Discovery or Vulnerability scan.')
        print_underscore()

    if mode == '(config)#':
        print('')
        print('nmap                 Configure Nmap options.')
        print('openvas              Configure OpenVas options.')
        print('seeds                Configure a seed router to automatically populate local_hosts.')
        print('show                 Show data.')
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


# -------------------------------------------------------------------------------
# Definitions to add data to the database
# -------------------------------------------------------------------------------


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
                               description='Seed Router Service Account',
                               perception_product_uuid=system_uuid)

        try:
            db_session.add(add_svc_user)
            db_session.flush()
            add_router = SeedRouter(ip_addr=ipaddr,
                                    svc_user_id=add_svc_user.id,
                                    host_name=hostname,
                                    perception_product_uuid=system_uuid)
            db_session.add(add_router)
            db_session.commit()

        except IntegrityError:
            db_session.rollback()
            user = db_session.query(SvcUser).filter_by(username=username).first()
            add_router = SeedRouter(ip_addr=ipaddr,
                                    svc_user_id=user.id,
                                    host_name=hostname,
                                    perception_product_uuid=system_uuid)
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
                                                      'run',
                                                      'firewalls',
                                                      'seeds',
                                                      'openvas',
                                                      'nmap',
                                                      'discovery',
                                                      'vuln_scan',
                                                      'all'
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
                    if cmd[0] == 'run':
                        try:
                            if cmd[1] == 'discovery':
                                try:
                                    if cmd[2] == 'on':

                                        SendToRabbitMQ('run_nmap_on %s' % cmd[3:],
                                                       system_uuid,
                                                       system_uuid)
                                        continue

                                except IndexError:
                                    pass

                            if cmd[1] == 'vuln_scan':
                                try:
                                    if cmd[2] == 'on':

                                        SendToRabbitMQ('run_openvas_on %s' % cmd[3:],
                                                       system_uuid,
                                                       system_uuid)
                                        continue

                                except IndexError:
                                    pass

                        except IndexError:
                            pass

                    # ------------------------------------------------------------------
                    # show commands
                    # ------------------------------------------------------------------
                    if cmd[0] == 'show':

                        if cmd[1] == '?':
                            display_show_help()

                        elif cmd[1] == 'seeds':
                            show_seeds()

                        elif cmd[1] == 'openvas':
                            show_openvas()

                        elif cmd[1] == 'all':
                            show_seeds()
                            show_openvas()
                            # show_nmap()

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
                    if cmd[0] == 'nmap' \
                            or cmd[0] == 'openvas' \
                            or cmd[0] == 'seeds':
                        mode = '(config/%s)#' % cmd[0]
                        continue
                        # --------------------------------------------------------------

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
