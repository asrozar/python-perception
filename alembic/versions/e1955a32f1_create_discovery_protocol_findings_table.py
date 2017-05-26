"""create discovery_protocol_findings table

Revision ID: e1955a32f1
Revises: 392c3a6e915
Create Date: 2015-06-25 13:00:36.962406

"""

# revision identifiers, used by Alembic.
revision = 'e1955a32f1'
down_revision = '392c3a6e915'
branch_labels = None
depends_on = None

from alembic import op
from sqlalchemy.dialects import postgresql
import sqlalchemy as sa
import datetime


def _get_date():
  return datetime.datetime.now()


def upgrade():
    op.create_table('discovery_protocol_findings',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('rsinfrastructure_id', sa.Integer, sa.ForeignKey('rsinfrastructure.id'), nullable=False),
                    sa.Column('remote_device_id', sa.Text, nullable=False),
                    sa.Column('ip_addr', postgresql.INET),
                    sa.Column('platform', sa.Text),
                    sa.Column('capabilities', sa.Text),
                    sa.Column('interface', sa.Text),
                    sa.Column('port_id', sa.Text),
                    sa.Column('discovery_version', sa.Integer),
                    sa.Column('protocol_hello', sa.Text),
                    sa.Column('vtp_domain', sa.Text),
                    sa.Column('native_vlan', sa.Integer),
                    sa.Column('duplex', sa.Text),
                    sa.Column('power_draw', sa.Text),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=False), default=_get_date))


def downgrade():
  op.drop_table('discovery_protocol_findings')
