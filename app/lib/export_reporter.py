import os
import xlsxwriter
from time import time
from app import db_session
from app.database.models import LocalHost,\
    InventoryHost,\
    InventorySvc, \
    RSInfrastructure, \
    DiscoveryProtocolFinding,\
    LocalSubnets


class ExportToXLSX(object):
    def __init__(self, dest):
        self.dest = dest
        self.run(dest)

    @staticmethod
    def infrastructure(report, top_row_format):
        rsi = db_session.query(RSInfrastructure).all()

        # Detailed host row format
        rsi_row_format = report.add_format()
        rsi_row_format.set_border(style=1)
        rsi_row_format.set_bg_color('#e6e6e6')

        # Format for text in row with host info
        rsi_row_wrapped_format = report.add_format()
        rsi_row_wrapped_format.set_border(style=1)
        rsi_row_wrapped_format.set_bg_color('#CCCCCC')
        rsi_row_wrapped_format.set_text_wrap('vjustify')

        # Build the rsi_worksheet
        rsi_worksheet = report.add_worksheet('Infrastructure')

        # Size up the overview worksheet"""
        rsi_worksheet.set_column('B:B', 15)
        rsi_worksheet.set_column('C:C', 20)
        rsi_worksheet.set_column('D:D', 18)
        rsi_worksheet.set_column('E:E', 118)
        rsi_worksheet.set_column('F:F', 10)
        rsi_worksheet.set_column('G:G', 22)
        rsi_worksheet.set_column('H:H', 20)

        rsi_worksheet.write('B2', 'IP Address', top_row_format)
        rsi_worksheet.write('C2', 'Hostname', top_row_format)
        rsi_worksheet.write('D2', 'Service User ID', top_row_format)
        rsi_worksheet.write('E2', 'Operating System', top_row_format)
        rsi_worksheet.write('F2', 'License', top_row_format)
        rsi_worksheet.write('G2', 'System Serial Number', top_row_format)
        rsi_worksheet.write('H2', 'System Model', top_row_format)

        row = 2
        col = 1

        for x in rsi:
            rsi_worksheet.write(row, col, x.ip_addr, rsi_row_format)
            rsi_worksheet.write(row, col + 1, x.host_name, rsi_row_format)
            rsi_worksheet.write(row, col + 2, x.svc_users.username, rsi_row_format)
            rsi_worksheet.write(row, col + 3, x.os_version, rsi_row_format)
            rsi_worksheet.write(row, col + 4, x.license_level, rsi_row_format)
            rsi_worksheet.write(row, col + 5, x.system_serial_number, rsi_row_format)
            rsi_worksheet.write(row, col + 6, x.model_number, rsi_row_format)
            row += 1

    @staticmethod
    def local_hosts(report, top_row_format):
        local_hosts = db_session.query(LocalHost).all()

        # Detailed host row format
        local_hosts_row_format = report.add_format()
        local_hosts_row_format.set_border(style=1)
        local_hosts_row_format.set_bg_color('#e6e6e6')

        # Format for text in row with host info
        local_hosts_row_format_row_wrapped_format = report.add_format()
        local_hosts_row_format_row_wrapped_format.set_border(style=1)
        local_hosts_row_format_row_wrapped_format.set_bg_color('#CCCCCC')
        local_hosts_row_format_row_wrapped_format.set_text_wrap('vjustify')

        # Build the rsi_worksheet
        local_hosts_worksheet = report.add_worksheet('Local Hosts')

        # Size up the overview worksheet"""
        local_hosts_worksheet.set_column('B:B', 15)
        local_hosts_worksheet.set_column('C:C', 18)
        local_hosts_worksheet.set_column('D:D', 18)
        local_hosts_worksheet.set_column('E:E', 18)

        local_hosts_worksheet.write('B2', 'Host', top_row_format)
        local_hosts_worksheet.write('C2', 'MAC Address', top_row_format)
        local_hosts_worksheet.write('D2', 'Adjacency Switch', top_row_format)
        local_hosts_worksheet.write('E2', 'Adjacency Interface', top_row_format)

        row = 2
        col = 1

        for x in local_hosts:
            local_hosts_worksheet.write(row, col, x.ip_addr, local_hosts_row_format)
            local_hosts_worksheet.write(row, col + 1, x.mac_addr, local_hosts_row_format)
            local_hosts_worksheet.write(row, col + 2, x.rsinfrastructure.ip_addr, local_hosts_row_format)
            local_hosts_worksheet.write(row, col + 3, x.adjacency_int, local_hosts_row_format)
            row += 1

    @staticmethod
    def local_subnet(report, top_row_format):
        local_subnets = db_session.query(LocalSubnets).all()

        # Detailed host row format
        local_subnets_row_format = report.add_format()
        local_subnets_row_format.set_border(style=1)
        local_subnets_row_format.set_bg_color('#e6e6e6')

        # Format for text in row with host info
        local_subnets_row_format_row_wrapped_format = report.add_format()
        local_subnets_row_format_row_wrapped_format.set_border(style=1)
        local_subnets_row_format_row_wrapped_format.set_bg_color('#CCCCCC')
        local_subnets_row_format_row_wrapped_format.set_text_wrap('vjustify')

        # Build the rsi_worksheet
        local_subnets_worksheet = report.add_worksheet('Local Subnets')

        # Size up the overview worksheet"""
        local_subnets_worksheet.set_column('B:B', 15)
        local_subnets_worksheet.set_column('C:C', 10)
        local_subnets_worksheet.set_column('D:D', 20)

        local_subnets_worksheet.write('B2', 'Subnet', top_row_format)
        local_subnets_worksheet.write('C2', 'Switch', top_row_format)
        local_subnets_worksheet.write('D2', 'Source Interface', top_row_format)

        row = 2
        col = 1

        for x in local_subnets:
            local_subnets_worksheet.write(row, col, x.subnet, local_subnets_row_format)
            local_subnets_worksheet.write(row, col + 1, x.rsinfrastructure.ip_addr, local_subnets_row_format)
            local_subnets_worksheet.write(row, col + 2, x.source_int, local_subnets_row_format)
            row += 1

    @staticmethod
    def inventory(report, top_row_format):
        inventory = db_session.query(InventoryHost).all()

        # Detailed host row format
        inventory_row_format = report.add_format()
        inventory_row_format.set_border(style=1)
        inventory_row_format.set_bg_color('#e6e6e6')

        # Format for text in row with host info
        inventory_row_format_row_wrapped_format = report.add_format()
        inventory_row_format_row_wrapped_format.set_border(style=1)
        inventory_row_format_row_wrapped_format.set_bg_color('#CCCCCC')
        inventory_row_format_row_wrapped_format.set_text_wrap('vjustify')

        # Build the rsi_worksheet
        inventory_worksheet = report.add_worksheet('Inventory')

        # Size up the overview worksheet"""
        inventory_worksheet.set_column('B:B', 15)
        inventory_worksheet.set_column('C:C', 18)
        inventory_worksheet.set_column('D:D', 33)
        inventory_worksheet.set_column('E:E', 25)
        inventory_worksheet.set_column('F:F', 18)
        inventory_worksheet.set_column('G:G', 22)
        inventory_worksheet.set_column('H:H', 20)

        inventory_worksheet.write('B2', 'IP address', top_row_format)
        inventory_worksheet.write('C2', 'MAC address', top_row_format)
        inventory_worksheet.write('D2', 'MAC vendor', top_row_format)
        inventory_worksheet.write('E2', 'Hostname', top_row_format)
        inventory_worksheet.write('F2', 'Adjacency Device', top_row_format)
        inventory_worksheet.write('G2', 'Infrastructure Model', top_row_format)
        inventory_worksheet.write('H2', 'Adjacency Interface', top_row_format)

        row = 2
        col = 1

        for x in inventory:
            inventory_worksheet.write(row, col, x.ip_addr, inventory_row_format)
            inventory_worksheet.write(row, col + 1, x.macaddr, inventory_row_format)
            inventory_worksheet.write(row, col + 2, x.mac_vendor.name, inventory_row_format)
            inventory_worksheet.write(row, col + 3, x.host_name, inventory_row_format)
            inventory_worksheet.write(row, col + 4, x.local_host.rsinfrastructure.ip_addr, inventory_row_format)
            inventory_worksheet.write(row, col + 5, x.local_host.rsinfrastructure.model_number, inventory_row_format)
            inventory_worksheet.write(row, col + 6, x.local_host.adjacency_int, inventory_row_format)
            row += 1

    @staticmethod
    def discovery_data(report, top_row_format):
        cdp = db_session.query(DiscoveryProtocolFinding).all()

        # Detailed host row format
        cdp_row_format = report.add_format()
        cdp_row_format.set_border(style=1)
        cdp_row_format.set_bg_color('#e6e6e6')

        # Format for text in row with host info
        cdp_row_format_row_wrapped_format = report.add_format()
        cdp_row_format_row_wrapped_format.set_border(style=1)
        cdp_row_format_row_wrapped_format.set_bg_color('#CCCCCC')
        cdp_row_format_row_wrapped_format.set_text_wrap('vjustify')

        # Build the rsi_worksheet
        cdp_worksheet = report.add_worksheet('Discovery Data')

        # Size up the overview worksheet"""
        cdp_worksheet.set_column('B:B', 15)
        cdp_worksheet.set_column('C:C', 20)
        cdp_worksheet.set_column('D:D', 15)
        cdp_worksheet.set_column('E:E', 25)
        cdp_worksheet.set_column('F:F', 20)
        cdp_worksheet.set_column('G:G', 22)
        cdp_worksheet.set_column('H:H', 22)
        cdp_worksheet.set_column('I:I', 16)
        cdp_worksheet.set_column('J:J', 110)
        cdp_worksheet.set_column('K:K', 12)
        cdp_worksheet.set_column('L:L', 12)
        cdp_worksheet.set_column('M:M', 10)
        cdp_worksheet.set_column('N:N', 12)

        cdp_worksheet.write('B2', 'Source Switch', top_row_format)
        cdp_worksheet.write('C2', 'Remote Device', top_row_format)
        cdp_worksheet.write('D2', 'Remote IP', top_row_format)
        cdp_worksheet.write('E2', 'Platform', top_row_format)
        cdp_worksheet.write('F2', 'Capabilities', top_row_format)
        cdp_worksheet.write('G2', 'Interface', top_row_format)
        cdp_worksheet.write('H2', 'Port ID', top_row_format)
        cdp_worksheet.write('I2', 'Discovery Version', top_row_format)
        cdp_worksheet.write('J2', 'Protocol Hello', top_row_format)
        cdp_worksheet.write('K2', 'VTP Domain', top_row_format)
        cdp_worksheet.write('L2', 'Native VLAN', top_row_format)
        cdp_worksheet.write('M2', 'Duplex', top_row_format)
        cdp_worksheet.write('N2', 'Power Draw', top_row_format)

        row = 2
        col = 1

        for x in cdp:
            cdp_worksheet.write(row, col, x.rsinfrastructure.ip_addr, cdp_row_format)
            cdp_worksheet.write(row, col + 1, x.remote_device_id, cdp_row_format)
            cdp_worksheet.write(row, col + 2, x.ip_addr, cdp_row_format)
            cdp_worksheet.write(row, col + 3, x.platform, cdp_row_format)
            cdp_worksheet.write(row, col + 4, x.capabilities, cdp_row_format)
            cdp_worksheet.write(row, col + 5, x.interface, cdp_row_format)
            cdp_worksheet.write(row, col + 6, x.port_id, cdp_row_format)
            cdp_worksheet.write(row, col + 7, x.discovery_version, cdp_row_format)
            cdp_worksheet.write(row, col + 8, x.protocol_hello, cdp_row_format)
            cdp_worksheet.write(row, col + 9, x.vtp_domain, cdp_row_format)
            cdp_worksheet.write(row, col + 10, x.native_vlan, cdp_row_format)
            cdp_worksheet.write(row, col + 11, x.duplex, cdp_row_format)
            cdp_worksheet.write(row, col + 12, x.power_draw, cdp_row_format)
            row += 1

    def run(self, dest):

        print('export using xlsx format')
        report = xlsxwriter.Workbook('%s/perception_report.%s.xlsx' % (dest, str(time())))

        top_row_format = report.add_format({'bold': True})
        top_row_format.set_border(style=1)
        top_row_format.set_bg_color('#B8B8B8')

        # Black row format at the top of each host detailed info
        black_row_format = report.add_format()
        black_row_format.set_border(style=1)
        black_row_format.set_bg_color('#000000')

        self.infrastructure(report, top_row_format)
        self.local_hosts(report, top_row_format)
        self.local_subnet(report, top_row_format)
        self.inventory(report, top_row_format)
        self.discovery_data(report, top_row_format)
        report.close()
        print('done exporting')
        return
