import syslog
from uuid import UUID


def get_product_uuid():
    # uuid
    with open('/etc/product_uuid', 'r') as f:

        try:
            system_uuid = f.read().rstrip()
            UUID(system_uuid)

            return system_uuid

        except ValueError:
            syslog.syslog(syslog.LOG_INFO, 'Error: System UUID not found')
            print('Error: System UUID not found')
            exit(99)
