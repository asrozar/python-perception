import datetime
from sqlalchemy import Column, Integer, Text, ForeignKey, Sequence, TIMESTAMP, String, PrimaryKeyConstraint
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


def _get_date():
    return datetime.datetime.now()


class Vendor(Base):
    __tablename__ = 'vendors'

    id = Column(Integer, Sequence('vendors_id_seq'), primary_key=True, nullable=False)
    name = Column(Text, unique=True, nullable=False)
    created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
    updated_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class Product(Base):
    __tablename__ = 'products'

    id = Column(Integer, Sequence('products_id_seq'), primary_key=True, nullable=False)
    cpe = Column(Text, nullable=False, unique=True)
    product_type = Column(Text, nullable=False)

    """Relation to tie vendors to products"""
    vendor_id = Column(Integer, ForeignKey('vendors.id'), nullable=False)
    vendor = relationship('Vendor', backref='products', order_by=id)

    name = Column(Text, nullable=False)
    version = Column(Text)
    product_update = Column(Text)
    edition = Column(Text)
    language = Column(Text)
    created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
    updated_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class OpenvasAdmin(Base):
    __tablename__ = 'openvas_admin'

    id = Column(Integer, Sequence('openvas_admin_id_seq'), primary_key=True, nullable=False)
    username = Column(Text, unique=True, nullable=False)
    password = Column(postgresql.UUID, nullable=False)
    created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
    updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)


class MACVendor(Base):
    __tablename__ = 'mac_vendors'

    id = Column(Integer, Sequence('mac_vendors_id_seq'), primary_key=True, nullable=False)
    name = Column(Text, unique=True, nullable=False)
    created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
    updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)


class SvcUser(Base):
        __tablename__ = 'svc_users'

        id = Column(Integer, primary_key=True, nullable=False)
        username = Column(String, nullable=False, unique=True)
        description = Column(String)

        created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
        updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)

        def __init__(self,
                     username=None,
                     description=None,
                     openvas_lsc_id=None):

            if description:
                self.description = description

            if username:
                self.username = username

            if openvas_lsc_id:
                self.openvas_lsc_id = openvas_lsc_id


class RSInfrastructure(Base):
    __tablename__ = 'rsinfrastructure'

    id = Column(Integer, Sequence('rsinfrastructure_id_seq'), primary_key=True, nullable=False)
    ip_addr = Column(postgresql.INET, unique=True, nullable=False)
    host_name = Column(Text, unique=True)

    """Relation to svc_user"""
    svc_user_id = Column(Integer, ForeignKey('svc_users.id'))
    svc_users = relationship('SvcUser', backref='rsinfrastructure', order_by=id)

    os_version = Column(Text)
    license_level = Column(Text)
    system_serial_number = Column(Text, unique=True)
    model_number = Column(Text)
    last_investigation = Column(TIMESTAMP(timezone=False))

    created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
    updated_at = Column(TIMESTAMP(timezone=False), default=_get_date)

    def __init__(self, svc_user_id,
                 ip_addr,
                 host_name=None,
                 os_version=None,
                 license_level=None,
                 system_serial_number=None,
                 model_number=None,
                 last_investigation=None):

        self.svc_user_id = svc_user_id
        self.ip_addr = ip_addr
        self.os_version = os_version
        self.license_level = license_level
        self.system_serial_number = system_serial_number
        self.model_number = model_number
        self.last_investigation = last_investigation

        if host_name:
            self.host_name = host_name


class MacAddrTable(Base):
    __tablename__ = 'mac_addr_tables'

    id = Column(Integer, primary_key=True, nullable=False)

    """Relation to rsinfrastructure"""
    rsinfrastructure_id = Column(Integer, ForeignKey('rsinfrastructure.id'))
    rsinfrastructure = relationship('RSInfrastructure', backref='mac_addr_tables', order_by=id)

    mac_addr = Column(postgresql.MACADDR, nullable=False)
    type = Column(Text)
    port = Column(Text)
    vlan = Column(Integer)

    created_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class RSAddr(Base):
    __tablename__ = 'rsaddrs'

    id = Column(Integer, primary_key=True, nullable=False)

    """Relation to rsinfrastructure"""
    rsinfrastructure_id = Column(Integer, ForeignKey('rsinfrastructure.id'))
    rsinfrastructure = relationship('RSInfrastructure', backref='rsaddrs', order_by=id)

    ip_addr = Column(postgresql.INET, nullable=False)

    created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
    updated_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class LocalSubnets(Base):
    __tablename__ = 'local_subnets'

    id = Column(Integer, primary_key=True, nullable=False)
    subnet = Column(postgresql.CIDR, nullable=False)

    """Relation to rsinfrastructure"""
    rsinfrastructure_id = Column(Integer, ForeignKey('rsinfrastructure.id'))
    rsinfrastructure = relationship('RSInfrastructure', backref='local_subnets', order_by=id)

    source_int = Column(Text)
    created_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class LocalHost(Base):
    __tablename__ = 'local_hosts'

    id = Column(Integer, primary_key=True, nullable=False)
    ip_addr = Column(postgresql.INET, nullable=False)

    """Relation to rsinfrastructure"""
    rsinfrastructure_id = Column(Integer, ForeignKey('rsinfrastructure.id'))
    rsinfrastructure = relationship('RSInfrastructure', backref='local_hosts', order_by=id)

    mac_addr = Column(postgresql.MACADDR, nullable=False)
    adjacency_int = Column(Text)
    created_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class InventoryHost(Base):
    __tablename__ = 'inventory_hosts'

    id = Column(Integer, Sequence('inventory_hosts_id_seq'), primary_key=True, nullable=False)

    local_host_id = Column(Integer, ForeignKey('local_hosts.id', ondelete='cascade'))
    local_host = relationship('LocalHost', backref='inventory_hosts', order_by=id)

    ip_addr = Column(postgresql.INET, unique=True)
    macaddr = Column(postgresql.MACADDR)
    host_type = Column(Text)

    """Relation mac address vendors"""
    mac_vendor_id = Column(Integer, ForeignKey('mac_vendors.id'))
    mac_vendor = relationship('MACVendor', backref='inventory_hosts', order_by=id)

    state = Column(Text)
    host_name = Column(Text)

    """Relation OS"""
    product_id = Column(Integer, ForeignKey('products.id'))
    product = relationship('Product', backref='inventory_hosts', order_by=id)

    arch = Column(Text)

    svc_user_id = Column(Integer, ForeignKey('svc_users.id'))
    svc_user = relationship('SvcUser', backref='inventory_hosts', order_by=id)

    info = Column(Text)
    comments = Column(Text)
    bad_ssh_key = Column(postgresql.BOOLEAN)
    last_openvas_scan = Column(TIMESTAMP(timezone=False))
    created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
    updated_at = Column(TIMESTAMP(timezone=False), onupdate=_get_date)


class InventorySvc(Base):
    __tablename__ = 'inventory_svcs'

    id = Column(Integer, Sequence('inventory_svcs_id_seq'), primary_key=True, nullable=False)

    """Relation to inventory inventory_host"""
    inventory_host_id = Column(Integer, ForeignKey('inventory_hosts.id', ondelete='cascade'))
    inventory_host = relationship('InventoryHost', backref='inventory_svcs', order_by=id)

    protocol = Column(Text)
    portid = Column(Integer)
    name = Column(Text)
    svc_product = Column(Text)
    extra_info = Column(Text)

    """Relation to tie products to inventory services"""
    product_id = Column(Integer, ForeignKey('products.id'))
    product = relationship('Product', backref='inventory_svcs', order_by=id)

    created_at = Column(TIMESTAMP(timezone=False), default=_get_date)
    updated_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class DiscoveryProtocolFinding(Base):
    __tablename__ = 'discovery_protocol_findings'

    id = Column(Integer, primary_key=True, nullable=False)

    """Relation to rsinfrastructure"""
    rsinfrastructure_id = Column(Integer, ForeignKey('rsinfrastructure.id'), nullable=False)
    rsinfrastructure = relationship('RSInfrastructure', backref='discovery_protocol_findings', order_by=id)

    remote_device_id = Column(Text, nullable=False)
    ip_addr = Column(postgresql.INET)
    platform = Column(Text)
    capabilities = Column(Text)
    interface = Column(Text)
    port_id = Column(Text)
    discovery_version = Column(Integer)
    protocol_hello = Column(Text)
    vtp_domain = Column(Text)
    native_vlan = Column(Integer)
    duplex = Column(Text)
    power_draw = Column(Text)
    created_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class SeedRouter(Base):
    __tablename__ = 'seed_routers'

    id = Column(Integer, Sequence('seed_routers_id_seq'), primary_key=True, nullable=False)
    ip_addr = Column(postgresql.INET, unique=True, nullable=False)
    host_name = Column(Text, unique=True)

    """Relation to svc_user"""
    svc_user_id = Column(Integer, ForeignKey('svc_users.id', ondelete='cascade'))
    svc_users = relationship('SvcUser', backref='seed_routers', order_by=id)

    created_at = Column(TIMESTAMP(timezone=False), default=_get_date)

    def __init__(self, svc_user_id,
                 ip_addr,
                 host_name=None):

        self.svc_user_id = svc_user_id
        self.ip_addr = ip_addr

        if host_name:
            self.host_name = host_name


class OpenvasLastUpdate(Base):
    __tablename__ = 'openvas_last_updates'

    id = Column(Integer, Sequence('openvas_last_updates_id_seq'), primary_key=True, nullable=False)
    updated_at = Column(TIMESTAMP(timezone=False), nullable=False)


class Vulnerability(Base):
    __tablename__ = 'vulnerabilities'

    id = Column(Integer, primary_key=True, nullable=False)
    name = Column(Text, nullable=False)
    cvss_score = Column(postgresql.FLOAT, nullable=False)
    bug_id = Column(Text)
    family = Column(Text)
    cve_id = Column(Text)

    """Relation to inventory_hosts"""
    inventory_host_id = Column(Integer, ForeignKey('inventory_hosts.id', ondelete='cascade'))
    inventory_host = relationship('InventoryHost', backref='vulnerabilities', order_by=id)

    port = Column(Text)
    threat_score = Column(Text)
    severity_score = Column(postgresql.FLOAT)
    xrefs = Column(Text)
    tags = Column(Text)
    validated = Column(postgresql.BOOLEAN)
    created_at = Column(TIMESTAMP(timezone=False), default=_get_date)


class DoNotSeed(Base):
    __tablename__ = 'do_not_seeds'

    id = Column(Integer, Sequence('do_not_seeds_id_seq'), primary_key=True, nullable=False)
    ip_addr = Column(postgresql.INET, unique=True, nullable=False)


class HostUsingSshv1(Base):
    __tablename__ = 'hosts_using_sshv1'

    id = Column(Integer, Sequence('hosts_using_sshv1_id_seq'), primary_key=True, nullable=False)
    ip_addr = Column(postgresql.INET, unique=True, nullable=False)


class HostWithBadSshKey(Base):
    __tablename__ = 'hosts_with_bad_ssh_key'

    id = Column(Integer, Sequence('hosts_with_bad_ssh_key_id_seq'), primary_key=True, nullable=False)
    ip_addr = Column(postgresql.INET, unique=True, nullable=False)
