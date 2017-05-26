"""create inventory_hosts table

Revision ID: 4e9f83654af
Revises: f5e18e930c
Create Date: 2015-06-23 16:49:21.424298

"""

# revision identifiers, used by Alembic.
revision = '4e9f83654af'
down_revision = 'f5e18e930c'
branch_labels = None
depends_on = None

from alembic import op
from sqlalchemy.dialects import postgresql
import sqlalchemy as sa
import datetime


def _get_date():
    return datetime.datetime.now()


def upgrade():
    op.create_table('inventory_hosts',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('local_host_id', sa.Integer, sa.ForeignKey('local_hosts.id', ondelete='cascade')),
                    sa.Column('ip_addr', postgresql.INET, unique=True, nullable=False),
                    sa.Column('macaddr', postgresql.MACADDR),
                    sa.Column('host_type', sa.Text),
                    sa.Column('mac_vendor_id', sa.Integer, sa.ForeignKey('mac_vendors.id')),
                    sa.Column('state', sa.Text),
                    sa.Column('host_name', sa.Text),
                    sa.Column('product_id', sa.Integer, sa.ForeignKey('products.id')),
                    sa.Column('arch', sa.Text),
                    sa.Column('svc_user_id', sa.Integer, sa.ForeignKey('svc_users.id')),
                    sa.Column('info', sa.Text),
                    sa.Column('comments', sa.Text),
                    sa.Column('bad_ssh_key', sa.Boolean),
                    sa.Column('last_openvas_scan', sa.TIMESTAMP(timezone=False)),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=False), default=_get_date),
                    sa.Column('updated_at', sa.TIMESTAMP(timezone=False), onupdate=_get_date))


def downgrade():
    op.drop_table('inventory_hosts')
