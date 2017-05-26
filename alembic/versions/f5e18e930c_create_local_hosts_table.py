"""create local_hosts table

Revision ID: f5e18e930c
Revises: 42122ee941b2
Create Date: 2015-07-07 11:47:16.334373

"""

# revision identifiers, used by Alembic.
revision = 'f5e18e930c'
down_revision = '42122ee941b2'
branch_labels = None
depends_on = None

from alembic import op
from sqlalchemy.dialects import postgresql
import sqlalchemy as sa
import datetime


def _get_date():
  return datetime.datetime.now()


def upgrade():
  op.create_table('local_hosts',
                  sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                  sa.Column('ip_addr', postgresql.INET, nullable=False),
                  sa.Column('rsinfrastructure_id', sa.Integer, sa.ForeignKey('rsinfrastructure.id'), nullable=False),
                  sa.Column('mac_addr', postgresql.MACADDR),
                  sa.Column('adjacency_int', sa.Text),
                  sa.Column('created_at', sa.TIMESTAMP(timezone=False), default=_get_date))


def downgrade():
  op.drop_table('local_hosts')
