#!/usr/bin/env python

from app import db_session, hostname_lookup
from signal import SIGTERM
from os import remove, path, kill, getpid, chdir, dup2, fork, setsid, umask
from sqlalchemy.exc import OperationalError
from time import sleep
from datetime import datetime, timedelta
from app.database.models import OpenvasAdmin,\
    OpenvasLastUpdate,\
    SeedRouter,\
    DiscoveryProtocolFinding, \
    SvcUser, \
    RSAddr, \
    RSInfrastructure, \
    DoNotSeed, \
    HostWithBadSshKey, \
    HostUsingSshv1
from app.lib.infrastructure import InterrogateRSI
from app.lib.openvas import setup_openvas,\
    update_openvas_db,\
    migrate_rebuild_db
from sqlalchemy.exc import IntegrityError, ProgrammingError
import threading
import syslog
import sys
import atexit


# For future use
class OpenVasUpdater(object):
    def __init__(self, interval=5*60):
        self.interval = interval

        t = threading.Thread(target=self.run, args=())
        t.start()

    def run(self):

        while True:

            try:

                try:
                    # verify openvas is configured
                    openvas_user = db_session.query(OpenvasAdmin).first()

                except OperationalError as e:  # if it's not working
                    syslog.syslog(syslog.LOG_INFO, 'Could not Query for OpenVas Admin')
                    syslog.syslog(syslog.LOG_INFO, e)
                    return

                if openvas_user is None:
                    syslog.syslog(syslog.LOG_INFO, 'OpenVas needs to be configured, this will take some time.')
                    setup_openvas()  # configured it
                    openvas_user = db_session.query(OpenvasAdmin).first()

                # update openvas NVT's, CERT data, and CPE's
                one_day_ago = datetime.now() - timedelta(hours=24)
                check_last_update = db_session.query(OpenvasLastUpdate).order_by(OpenvasLastUpdate.id.desc()).first()

                if check_last_update is None or check_last_update.updated_at <= one_day_ago:
                    syslog.syslog(syslog.LOG_INFO, 'Updating OpenVas NVT, SCAP and CERT database')

                    try:
                        update_openvas_db()

                        # migrate and rebuild the db
                        migrate_rebuild_db()

                        add_update_info = OpenvasLastUpdate(updated_at=datetime.now())
                        db_session.add(add_update_info)
                        db_session.commit()
                        syslog.syslog(syslog.LOG_INFO,
                                      'OpenVas NVT, SCAP and CERT database updated successfully [DB update is now complete]')

                    except Exception as e:
                        db_session.rollback()
                        syslog.syslog(syslog.LOG_INFO, e)
                        print(e)

            except Exception as openvas_updater_e:
                syslog.syslog(syslog.LOG_INFO, str(openvas_updater_e))

            sleep(self.interval)


class RSInventoryUpdater(object):
    def __init__(self, interval=6*(60*60)):
        self.interval = interval
        t = threading.Thread(target=self.run, args=())
        t.start()

    def run(self):

        while True:

            try:

                rsinventory = db_session.query(RSInfrastructure).all()

                for r in rsinventory:

                    InterrogateRSI(r.host_name,
                                   r.ip_addr,
                                   r.svc_users.username,
                                   r.svc_user_id)

            except ProgrammingError:
                syslog.syslog(syslog.LOG_INFO, 'RSInventorySpider() can not read from the database.')

            sleep(self.interval)


class DiscoveryProtocolSpider(object):
    def __init__(self, interval=120):
        self.interval = interval
        t = threading.Thread(target=self.run, args=())
        t.start()

    def run(self):

        while True:

            try:

                discovery_findings = db_session.query(DiscoveryProtocolFinding)\
                    .filter(DiscoveryProtocolFinding.ip_addr != None) \
                    .filter(DiscoveryProtocolFinding.platform != 'VMware ESX')\
                    .filter(DiscoveryProtocolFinding.capabilities.ilike('%Switch%')).all()

                for finding in discovery_findings:
                    rtr_list = list()

                    do_not_seed = db_session.query(DoNotSeed).filter(DoNotSeed.ip_addr == finding.ip_addr).first()
                    if do_not_seed:
                        if do_not_seed.ip_addr not in rtr_list:
                            rtr_list.append(do_not_seed.ip_addr)

                    host_with_bad_key = db_session.query(HostWithBadSshKey).filter(HostWithBadSshKey.ip_addr == finding.ip_addr).first()
                    if host_with_bad_key:
                        if host_with_bad_key.ip_addr not in rtr_list:
                            rtr_list.append(host_with_bad_key.ip_addr)

                    host_using_sshv1 = db_session.query(HostUsingSshv1).filter(HostUsingSshv1.ip_addr == finding.ip_addr).first()
                    if host_using_sshv1:
                        if host_using_sshv1.ip_addr not in rtr_list:
                            rtr_list.append(host_using_sshv1.ip_addr)

                    rsiaddr_exists = db_session.query(RSAddr).filter(RSAddr.ip_addr == finding.ip_addr).first()
                    if rsiaddr_exists:
                        if rsiaddr_exists.ip_addr not in rtr_list:
                            rtr_list.append(rsiaddr_exists.ip_addr)

                    if not rtr_list:

                        try:
                            hostname = hostname_lookup(finding.ip_addr)

                            find_seed_account = db_session.query(SvcUser).filter(SvcUser.description == 'Seed Router Service Account').first()

                            is_ip_addr_in_seed = db_session.query(SeedRouter).filter(SeedRouter.ip_addr == finding.ip_addr).first()

                            if is_ip_addr_in_seed is None:

                                add_to_seed = SeedRouter(ip_addr=finding.ip_addr,
                                                         svc_user_id=find_seed_account.id,
                                                         host_name=hostname)
                                db_session.add(add_to_seed)
                                db_session.commit()

                        except IntegrityError:
                            db_session.rollback()

                        except Exception as d_e:
                            db_session.rollback()
                            syslog.syslog(syslog.LOG_INFO, str(d_e))

            except ProgrammingError:
                syslog.syslog(syslog.LOG_INFO, 'DiscoveryProtocolSpider() can not read from the database.')

            sleep(self.interval)


class SeedStarter(object):
    def __init__(self, interval=15):
        self.interval = interval
        t = threading.Thread(target=self.run, args=())
        t.start()

    def run(self):

        while True:

            try:

                seed_routers = db_session.query(SeedRouter).all()
                if seed_routers is not None:

                    for i in seed_routers:
                        rtr_list = list()

                        do_not_seed = db_session.query(DoNotSeed).filter(DoNotSeed.ip_addr == i.ip_addr).first()
                        if do_not_seed:
                            if do_not_seed.ip_addr not in rtr_list:
                                rtr_list.append(do_not_seed.ip_addr)

                        rsaddr_exists = db_session.query(RSAddr).filter(RSAddr.ip_addr == i.ip_addr).first()
                        if rsaddr_exists:
                            if rsaddr_exists.ip_addr not in rtr_list:
                                rtr_list.append(rsaddr_exists.ip_addr)

                        host_with_bad_key = db_session.query(HostWithBadSshKey).filter(HostWithBadSshKey.ip_addr == i.ip_addr).first()
                        if host_with_bad_key:
                            if host_with_bad_key.ip_addr not in rtr_list:
                                rtr_list.append(host_with_bad_key.ip_addr)

                        host_using_sshv1 = db_session.query(HostUsingSshv1).filter(HostUsingSshv1.ip_addr == i.ip_addr).first()
                        if host_using_sshv1:
                            if host_using_sshv1.ip_addr not in rtr_list:
                                rtr_list.append(host_using_sshv1.ip_addr)

                        if rtr_list:

                            try:
                                db_session.delete(i)
                                db_session.commit()
                                continue
                            except Exception as e:
                                syslog.syslog(syslog.LOG_INFO,
                                              'PerceptionD Exception caught trying to delete %s from SeedRouter with addr %s'
                                              % (str(i.id), str(i.ip_addr)))
                                syslog.syslog(syslog.LOG_INFO, str(e))
                                db_session.rollback()
                                continue

                        # if so get info
                        try:

                            # get info from seed
                            InterrogateRSI(i.host_name,
                                           i.ip_addr,
                                           i.svc_users.username,
                                           i.svc_user_id,
                                           True)

                        except Exception as seed_e:
                            syslog.syslog(syslog.LOG_INFO, 'InterrogateRSI Exception caught' % seed_e)
                            return

            except ProgrammingError:
                syslog.syslog(syslog.LOG_INFO, 'SeedStarter() can not read from the database.')

            sleep(self.interval)


class PerceptionDaemon(object):
    """
    Usage: subclass the PerceptionDaemon class and override the run() method
    """

    def __init__(self, pidfile, stdin='/dev/null', stdout='/dev/null', stderr='/dev/null', interval=5):
        self.stdin = stdin
        self.stdout = stdout
        self.stderr = stderr
        self.pidfile = pidfile
        self.interval = interval

    def daemonize(self):
        """
        do the UNIX double-fork magic, see Stevens' "Advanced
        Programming in the UNIX Environment" for details (ISBN 0201563177)
        http://www.erlenstar.demon.co.uk/unix/faq_2.html#SEC16
        """
        try:
            pid = fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write("fork #1 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # decouple from parent environment
        chdir("/")
        setsid()
        umask(0)

        # do second fork
        try:
            pid = fork()
            if pid > 0:
                # exit from second parent
                sys.exit(0)
        except OSError as e:
            sys.stderr.write("fork #2 failed: %d (%s)\n" % (e.errno, e.strerror))
            sys.exit(1)

        # redirect standard file descriptors
        sys.stdout.flush()
        sys.stderr.flush()
        si = file(self.stdin, 'r')
        so = file(self.stdout, 'a+')
        se = file(self.stderr, 'a+', 0)
        dup2(si.fileno(), sys.stdin.fileno())
        dup2(so.fileno(), sys.stdout.fileno())
        dup2(se.fileno(), sys.stderr.fileno())

        # write pidfile
        atexit.register(self.delpid)
        pid = str(getpid())
        file(self.pidfile, 'w+').write("%s\n" % pid)

    def delpid(self):
        remove(self.pidfile)

    def start(self):
        """
        Start the daemon
        """
        # Check for a pidfile to see if the daemon already runs
        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if pid:
            message = "pidfile %s already exist. PerceptionDaemon already running?\n"
            sys.stderr.write(message % self.pidfile)
            sys.exit(1)

        # Start the daemon
        self.daemonize()
        self.run_d()
        syslog.syslog(syslog.LOG_INFO, 'Starting PerceptionDaemon')

    def stop(self):
        """
        Stop the daemon
        """
        # Get the pid from the pidfile
        try:
            pf = file(self.pidfile, 'r')
            pid = int(pf.read().strip())
            pf.close()
        except IOError:
            pid = None

        if not pid:
            message = "pidfile %s does not exist. PerceptionDaemon not running?\n"
            sys.stderr.write(message % self.pidfile)
            return  # not an error in a restart

        # Try killing the daemon process
        try:
            while 1:
                kill(pid, SIGTERM)
                sleep(0.1)
        except OSError as err:
            err = str(err)
            if err.find("No such process") > 0:
                if path.exists(self.pidfile):
                    remove(self.pidfile)
            else:
                print(str(err))
                sys.exit(1)
        syslog.syslog(syslog.LOG_INFO, 'Stopping PerceptionDaemon')

    def restart(self):
        """
        Restart the daemon
        """
        self.stop()
        self.start()

    @staticmethod
    def run_d():
        """
        You should override this method when you subclass PerceptionDaemon. It will be called after the process has been
        daemonized by start() or restart().
        """
        SeedStarter()
        DiscoveryProtocolSpider()
        RSInventoryUpdater()
        OpenVasUpdater()
