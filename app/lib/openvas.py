from OpenSSL import crypto
from datetime import datetime
from os import path, makedirs, system
from subprocess import call
from re import match, search
from subprocess import check_output, CalledProcessError, PIPE
from time import sleep
from app.lib.xml_output_parser import parse_openvas_xml
from app.database.models import OpenvasAdmin, OpenvasLastUpdate
from app import db_session, system_uuid
import syslog

redis_conf = '/etc/redis/redis.conf'
port_regex = 's/^\(#.\)\?port.*$/port 0/'
unixsocket_regex = 's/^\(#.\)\?unixsocket \/.*$/unixsocket \/var\/run\/redis\/redis.sock/'
unixsocketperm_regex = 's/^\(#.\)\?unixsocketperm.*$/unixsocketperm 700/'
cacert_pem = '/var/lib/openvas/CA/cacert.pem'
servercert_pem = '/var/lib/openvas/CA/servercert.pem'
clientkey_pem = '/var/lib/openvas/private/CA/clientkey.pem'
clientcert_pem = '/var/lib/openvas/CA/clientcert.pem'


def setup_openvas():

    # verify redis configuration
    # validate that unixsocket is enabled
    if check_redis_unixsocket_conf(redis_conf) is not 1:
        # disable tcp in redis configuration
        find_replace(port_regex, redis_conf)
        # enable unixsocket
        find_replace(unixsocket_regex, redis_conf)
        find_replace(unixsocketperm_regex, redis_conf)

    verify_existing_certs = call(['openvas-manage-certs', '-V'])

    if verify_existing_certs != 0:
        call(['openvas-manage-certs', '-af'])

    # update openvas CERT, SCAP and NVT data
    update_openvas_db()

    # migrate and rebuild the db
    migrate_rebuild_db()

    # create the admin user
    try:
        new_user = check_output(["openvasmd", "--create-user=perception_admin"]).decode()
        new_user_passwd = search(r'\w+[-]\w+[-]\w+[-]\w+[-]\w+', new_user).group(0)

    except CalledProcessError:
        call(['openvasmd', '--delete-user=perception_admin'])
        new_user = check_output(["openvasmd", "--create-user=perception_admin"]).decode()
        new_user_passwd = search(r'\w+[-]\w+[-]\w+[-]\w+[-]\w+', new_user).group(0)

    # create the GNU Privacy Guard directory for LSC (Local Security Checks) accounts
    try:
        makedirs('/var/lib/openvas/gnupg')
    except OSError:
        ''

    add_user = OpenvasAdmin(perception_product_uuid=system_uuid,
                            username='perception_admin',
                            password=new_user_passwd)
    db_session.add(add_user)

    add_update_info = OpenvasLastUpdate(updated_at=datetime.now(), perception_product_uuid=system_uuid)
    db_session.add(add_update_info)

    db_session.commit()


def check_redis_unixsocket_conf(conf):
    with open(conf, mode='r') as f:
        for line in f:
            if match(r'^unixsocket\s+', line):
                return 1
            else:
                return 0


def find_replace(sed_regex, conf):
    system('sed -i -e \'%s\' %s' % (sed_regex, conf))


def verify_certificate_chain(cert_str, trusted_certs):
    ca_cert_list = list()

    with open(cert_str) as f1:
        client_cert = f1.read()

    with open(trusted_certs) as f2:
        ca_cert = f2.read()
        ca_cert_list.append(ca_cert)

    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, client_cert.encode())
    trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, ca_cert.encode())

    # Create a certificate store and add your trusted certs
    store = crypto.X509Store()
    store.add_cert(trusted_cert)

    # Create a certificate context using the store and the downloaded certificate
    store_ctx = crypto.X509StoreContext(store, certificate)

    # Verify the certificate. Returns None if it can validate the certificate
    store_ctx.verify_certificate()

    return True


def update_openvas_db():
    syslog.syslog(syslog.LOG_INFO, 'Attempting to update OpenVas, this may take some time')
    greenbone_nvt_sync = call(['greenbone-nvt-sync'], stdout=PIPE)

    if greenbone_nvt_sync == 0:
        syslog.syslog(syslog.LOG_INFO, 'OpenVas NVT synced successfully')
        greenbone_scapdata_sync = call(['greenbone-scapdata-sync'], stdout=PIPE)

        if greenbone_scapdata_sync == 0:
            syslog.syslog(syslog.LOG_INFO, 'OpenVas Scap Data synced successfully ')
            greenbone_certdata_sync = call(['greenbone-certdata-sync'], stdout=PIPE)

            if greenbone_certdata_sync == 0:
                syslog.syslog(syslog.LOG_INFO, 'OpenVas Cert data synced successfully')

            elif greenbone_certdata_sync != 0:
                syslog.syslog(syslog.LOG_INFO, 'Failed tp sync OpenVas Cert Data')

        elif greenbone_scapdata_sync != 0:
            syslog.syslog(syslog.LOG_INFO, 'Failed to sync OpenVas Scap Data')

    elif greenbone_nvt_sync != 0:
        syslog.syslog(syslog.LOG_INFO, 'Failed to sync OpenVas NVT')


def migrate_rebuild_db():
    # stop services and migrate database
    stop_manager = call(['service', 'openvas-manager', 'stop'], stdout=PIPE)

    if stop_manager == 0:
        openvas_stop_scanner = call(['service', 'openvas-scanner', 'stop'], stdout=PIPE)

        if openvas_stop_scanner == 0:
            openvasssd = call(['openvassd'], stdout=PIPE)

            if stop_manager == 0:
                syslog.syslog(syslog.LOG_INFO, 'Migrating the OpenVas database')
                openvasmd_migrate = call(['openvasmd', '--migrate'], stdout=PIPE)

                if openvasmd_migrate == 0:
                    syslog.syslog(syslog.LOG_INFO, 'Rebuilding the OpenVas database, this will take some time')
                    openvasmd_rebuild = call(['openvasmd', '--rebuild'])

                    if openvasmd_rebuild == 0:
                        syslog.syslog(syslog.LOG_INFO, 'OpenVas rebuild database was successful')
                        killall_openvas = call(['killall', 'openvassd'], stdout=PIPE)

                        sleep(15)

                        if killall_openvas == 0:
                            start_openvas_scanner = call(['service', 'openvas-scanner', 'start'], stdout=PIPE)

                            if start_openvas_scanner == 0:
                                start_openvas_manager = call(['service', 'openvas-manager', 'start'], stdout=PIPE)

                                if start_openvas_manager != 0:
                                    syslog.syslog(syslog.LOG_INFO, 'Failed to start OpenVas Manager')

                            if start_openvas_scanner != 0:
                                syslog.syslog(syslog.LOG_INFO, 'Failed to start OpenVas Scanner')

                        elif killall_openvas != 0:
                            syslog.syslog(syslog.LOG_INFO, 'Failed to kill all OpenVas Services')

                    elif openvasmd_rebuild != 0:
                        syslog.syslog(syslog.LOG_INFO, 'Failed to rebuild OpenVas database')

                elif openvasmd_migrate != 0:
                    syslog.syslog(syslog.LOG_INFO, 'Failed to run OpenVas Migrate')

            elif openvasssd != 0:
                syslog.syslog(syslog.LOG_INFO, 'Failed openvassd')

        elif openvas_stop_scanner != 0:
            syslog.syslog(syslog.LOG_INFO, 'Failed to stop  OpenVas Scanner')

    elif stop_manager != 0:
        syslog.syslog(syslog.LOG_INFO, 'Failed to stop  OpenVas Manager')


def create_targets(targets_name, openvas_user_username, openvas_user_password, scan_list):
    create_target_cli = '<create_target>' \
                        '<name>%s</name>' \
                        '<hosts>%s</hosts>' \
                        '</create_target>' % (targets_name, ', '.join(scan_list))

    create_target_response = check_output(['omp',
                                           '--port=9390',
                                           '--host=localhost',
                                           '--username=%s' % openvas_user_username,
                                           '--password=%s' % openvas_user_password,
                                           '--xml=%s' % create_target_cli]).decode()

    error = search(r'status=\"503\"', create_target_response)

    if error:
        syslog.syslog(syslog.LOG_INFO, str('OpenVas error: %s' % create_target_response))
        return

    create_target_response_id = search(r'\w+[-]\w+[-]\w+[-]\w+[-]\w+', create_target_response)

    if create_target_response_id:
        return create_target_response_id.group(0)


#def create_targets_with_smb_lsc(targets_name, openvas_user_username, openvas_user_password, lsc_id, smb_scan_list):
#    create_target_cli = '<create_target>' \
#                        '<name>%s</name>' \
#                        '<hosts>%s</hosts>' \
#                        '<smb_lsc_credential id="%s"/>' \
#                        '</create_target>' % (targets_name, ', '.join(smb_scan_list), lsc_id)

#    create_target_response = check_output(['omp',
#                                           '--port=9390',
#                                           '--host=localhost',
#                                           '--username=%s' % openvas_user_username,
#                                           '--password=%s' % openvas_user_password,
#                                           '--xml=%s' % create_target_cli]).decode()

#    create_target_response_id = search(r'\w+[-]\w+[-]\w+[-]\w+[-]\w+', create_target_response).group(0)

#    return create_target_response_id


#def create_targets_with_ssh_lsc(targets_name, openvas_user_username, openvas_user_password, lsc_id, ssh_scan_list):
#    create_target_cli = '<create_target>' \
#                        '<name>%s</name>' \
#                        '<hosts>%s</hosts>' \
#                        '<ssh_lsc_credential id="%s"/>' \
#                        '</create_target>' % (targets_name, ', '.join(ssh_scan_list), lsc_id)

#    create_target_response = check_output(['omp',
#                                           '--port=9390',
#                                           '--host=localhost',
#                                           '--username=%s' % openvas_user_username,
#                                           '--password=%s' % openvas_user_password,
#                                           '--xml=%s' % create_target_cli]).decode()

#    create_target_response_id = search(r'\w+[-]\w+[-]\w+[-]\w+[-]\w+', create_target_response).group(0)

#    return create_target_response_id


def create_task(task_name, target_id, openvas_user_username, openvas_user_password):
    create_task_cli = '<create_task>' \
                      '<name>%s</name>' \
                      '<comment></comment>' \
                      '<config id="daba56c8-73ec-11df-a475-002264764cea"/>' \
                      '<target id="%s"/>' \
                      '</create_task>' % (task_name, target_id)

    create_task_response = check_output(['omp',
                                         '--port=9390',
                                         '--host=localhost',
                                         '--username=%s' % openvas_user_username,
                                         '--password=%s' % openvas_user_password,
                                         '--xml=%s' % create_task_cli]).decode()

    error = search(r'status=\"503\"', create_task_response)

    if error:
        syslog.syslog(syslog.LOG_INFO, str('OpenVas error: %s' % create_task_response))
        return

    create_task_response_id = search(r'\w+[-]\w+[-]\w+[-]\w+[-]\w+', create_task_response)

    if create_task_response_id:

        return create_task_response_id.group(0)


#def create_lsc_credential(name, login, password, openvas_user_username, openvas_user_password):

#    create_lsc_credential_cli = '<create_lsc_credential>' \
#                                '<name>%s</name>' \
#                                '<login>%s</login>' \
#                                '<password>%s</password>' \
#                                '<comment></comment>' \
#                                '</create_lsc_credential>' % (name, login, password)

#    create_lsc_credential_cli_response = check_output(['omp',
#                                                       '--port=9390',
#                                                       '--host=localhost',
#                                                       '--username=%s' % openvas_user_username,
#                                                       '--password=%s' % openvas_user_password,
#                                                       '--xml=%s' % create_lsc_credential_cli]).decode()

#    return parse_openvas_xml(create_lsc_credential_cli_response)


#def get_lsc_crdentials(openvas_user_username, openvas_user_password):
#    get_lsc_credential_cli = '<get_lsc_credentials/>'

#    get_lsc_credential_cli_response = check_output(['omp',
#                                                    '--port=9390',
#                                                    '--host=localhost',
#                                                    '--username=%s' % openvas_user_username,
#                                                    '--password=%s' % openvas_user_password,
#                                                    '--xml=%s' % get_lsc_credential_cli]).decode()

#    return parse_openvas_xml(get_lsc_credential_cli_response)


def start_task(task_id, openvas_user_username, openvas_user_password):

    start_task_cli = '<start_task task_id="%s"/>' % task_id
    start_task_response = check_output(['omp',
                                        '--port=9390',
                                        '--host=localhost',
                                        '--username=%s' % openvas_user_username,
                                        '--password=%s' % openvas_user_password,
                                        '--xml=%s' % start_task_cli]).decode()

    error = search(r'status=\"503\"', start_task_response)

    if error:
        syslog.syslog(syslog.LOG_INFO, str('OpenVas error: %s' % start_task_response))
        return

    xml_report_id = search(r'\w+[-]\w+[-]\w+[-]\w+[-]\w+', start_task_response)

    if xml_report_id:
        return xml_report_id.group(0)


def check_task(task_id, openvas_user_username, openvas_user_password):
    get_task_cli = '<get_tasks task_id="%s"/>' % task_id
    get_task_cli_response = check_output(['omp',
                                          '--port=9390',
                                          '--host=localhost',
                                          '--username=%s' % openvas_user_username,
                                          '--password=%s' % openvas_user_password,
                                          '--xml=%s' % get_task_cli]).decode()

    return parse_openvas_xml(get_task_cli_response)


def get_report(report_id, openvas_user_username, openvas_user_password):
    get_report_cli = '<get_reports report_id="%s"/>' % report_id
    get_report_cli_response = check_output(['omp',
                                            '--port=9390',
                                            '--host=localhost',
                                            '--username=%s' % openvas_user_username,
                                            '--password=%s' % openvas_user_password,
                                            '--xml=%s' % get_report_cli]).decode()

    parse_openvas_xml(get_report_cli_response)


def delete_task(task_id, openvas_user_username, openvas_user_password):
    delete_task_cli = '<delete_task task_id="%s"/>' % task_id
    delete_task_cli_response = check_output(['omp',
                                             '--port=9390',
                                             '--host=localhost',
                                             '--username=%s' % openvas_user_username,
                                             '--password=%s' % openvas_user_password,
                                             '--xml=%s' % delete_task_cli]).decode()

    return delete_task_cli_response


def delete_targets(target_id, openvas_user_username, openvas_user_password):
    delete_targets_cli = '<delete_target target_id="%s"/>' % target_id
    delete_targets_cli_response = check_output(['omp',
                                                '--port=9390',
                                                '--host=localhost',
                                                '--username=%s' % openvas_user_username,
                                                '--password=%s' % openvas_user_password,
                                                '--xml=%s' % delete_targets_cli]).decode()

    return delete_targets_cli_response


def delete_reports(report_id, openvas_user_username, openvas_user_password):
    delete_report_cli = '<delete_report report_id="%s"/>' % report_id
    delete_report_cli_response = check_output(['omp',
                                               '--port=9390',
                                               '--host=localhost',
                                               '--username=%s' % openvas_user_username,
                                               '--password=%s' % openvas_user_password,
                                               '--xml=%s' % delete_report_cli]).decode()

    return delete_report_cli_response
