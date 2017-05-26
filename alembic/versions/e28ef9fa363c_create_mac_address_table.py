"""create mac address table

Revision ID: e28ef9fa363c
Revises: 4e051e1c257
Create Date: 2017-03-15 20:02:50.913898

"""
from alembic import op
from sqlalchemy.dialects import postgresql
import sqlalchemy as sa
import datetime

# revision identifiers, used by Alembic.
revision = 'e28ef9fa363c'
down_revision = '4e051e1c257'
branch_labels = None
depends_on = None


def _get_date():
    return datetime.datetime.now()


def upgrade():
    op.create_table('mac_addr_tables',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('rsinfrastructure_id', sa.Integer, sa.ForeignKey('rsinfrastructure.id'), nullable=False),
                    sa.Column('mac_addr', postgresql.MACADDR),
                    sa.Column('type', sa.Text),
                    sa.Column('port', sa.Text),
                    sa.Column('vlan', sa.INTEGER),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=False), default=_get_date))


def downgrade():
    op.drop_table('mac_addr_tables')
