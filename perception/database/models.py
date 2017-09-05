import datetime
from sqlalchemy import Column, Integer, Text, ForeignKey, TIMESTAMP, String
from sqlalchemy.dialects import postgresql
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship

Base = declarative_base()


def _get_date():
    return datetime.datetime.now()


class OpenvasAdmin(Base):
    __tablename__ = 'openvas_admin'

    id = Column(Integer, primary_key=True, nullable=False)
    perception_product_uuid = Column(postgresql.UUID, nullable=False)
    username = Column(Text, nullable=False)
    password = Column(postgresql.UUID, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), default=_get_date)
    updated_at = Column(TIMESTAMP(timezone=True), default=_get_date)


class SvcUser(Base):
    __tablename__ = 'svc_users'

    id = Column(Integer, primary_key=True, nullable=False)
    perception_product_uuid = Column(postgresql.UUID, nullable=False)
    username = Column(String, nullable=False, unique=True)
    description = Column(String)

    created_at = Column(TIMESTAMP(timezone=True), default=_get_date)
    updated_at = Column(TIMESTAMP(timezone=True), default=_get_date)

    def __init__(self,
                 perception_product_uuid,
                 username=None,
                 description=None):

        self.perception_product_uuid = perception_product_uuid

        if description:
            self.description = description

        if username:
            self.username = username


class RSInfrastructure(Base):
    __tablename__ = 'rsinfrastructure'

    id = Column(Integer, primary_key=True, nullable=False)
    perception_product_uuid = Column(postgresql.UUID, nullable=False)
    ip_addr = Column(postgresql.INET, unique=True, nullable=False)
    host_name = Column(Text, unique=True)

    """Relation to svc_user"""
    svc_user_id = Column(Integer, ForeignKey('svc_users.id'))
    svc_users = relationship('SvcUser', backref='rsinfrastructure', order_by=id)

    created_at = Column(TIMESTAMP(timezone=True), default=_get_date)
    updated_at = Column(TIMESTAMP(timezone=True), default=_get_date)

    def __init__(self,
                 perception_product_uuid,
                 svc_user_id,
                 ip_addr,
                 host_name=None):

        self.perception_product_uuid = perception_product_uuid
        self.svc_user_id = svc_user_id
        self.ip_addr = ip_addr

        if host_name:
            self.host_name = host_name


class RSAddr(Base):
    __tablename__ = 'rsaddrs'

    id = Column(Integer, primary_key=True, nullable=False)
    perception_product_uuid = Column(postgresql.UUID, nullable=False)

    """Relation to rsinfrastructure"""
    rsinfrastructure_id = Column(Integer, ForeignKey('rsinfrastructure.id'))
    rsinfrastructure = relationship('RSInfrastructure', backref='rsaddrs', order_by=id)

    ip_addr = Column(postgresql.INET, nullable=False)

    created_at = Column(TIMESTAMP(timezone=True), default=_get_date)
    updated_at = Column(TIMESTAMP(timezone=True), default=_get_date)


class DiscoveryProtocolFinding(Base):
    __tablename__ = 'discovery_protocol_findings'

    id = Column(Integer, primary_key=True, nullable=False)
    perception_product_uuid = Column(postgresql.UUID, nullable=False)

    """Relation to rsinfrastructure"""
    rsinfrastructure_id = Column(Integer, ForeignKey('rsinfrastructure.id'), nullable=False)
    rsinfrastructure = relationship('RSInfrastructure', backref='discovery_protocol_findings', order_by=id)

    ip_addr = Column(postgresql.INET)
    platform = Column(Text)
    capabilities = Column(Text)
    created_at = Column(TIMESTAMP(timezone=True), default=_get_date)


class SeedRouter(Base):
    __tablename__ = 'seed_routers'

    id = Column(Integer, primary_key=True, nullable=False)
    perception_product_uuid = Column(postgresql.UUID, nullable=False)
    ip_addr = Column(postgresql.INET, unique=True, nullable=False)
    host_name = Column(Text, unique=True)

    """Relation to svc_user"""
    svc_user_id = Column(Integer, ForeignKey('svc_users.id', ondelete='cascade'))
    svc_users = relationship('SvcUser', backref='seed_routers', order_by=id)

    created_at = Column(TIMESTAMP(timezone=True), default=_get_date)

    def __init__(self,
                 perception_product_uuid,
                 svc_user_id,
                 ip_addr,
                 host_name=None):

        self.perception_product_uuid = perception_product_uuid
        self.svc_user_id = svc_user_id
        self.ip_addr = ip_addr

        if host_name:
            self.host_name = host_name


class OpenvasLastUpdate(Base):
    __tablename__ = 'openvas_last_updates'

    id = Column(Integer, primary_key=True, nullable=False)
    perception_product_uuid = Column(postgresql.UUID, nullable=False)
    updated_at = Column(TIMESTAMP(timezone=True), nullable=False)


class DoNotSeed(Base):
    __tablename__ = 'do_not_seeds'

    id = Column(Integer, primary_key=True, nullable=False)
    perception_product_uuid = Column(postgresql.UUID, nullable=False)
    ip_addr = Column(postgresql.INET, unique=True, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), default=_get_date)


class HostUsingSshv1(Base):
    __tablename__ = 'hosts_using_sshv1'

    id = Column(Integer, primary_key=True, nullable=False)
    perception_product_uuid = Column(postgresql.UUID, nullable=False)
    ip_addr = Column(postgresql.INET, unique=True, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), default=_get_date)


class HostWithBadSshKey(Base):
    __tablename__ = 'hosts_with_bad_ssh_key'

    id = Column(Integer, primary_key=True, nullable=False)
    perception_product_uuid = Column(postgresql.UUID, nullable=False)
    ip_addr = Column(postgresql.INET, unique=True, nullable=False)
    created_at = Column(TIMESTAMP(timezone=True), default=_get_date)
