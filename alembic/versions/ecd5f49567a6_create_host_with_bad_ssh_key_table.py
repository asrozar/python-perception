"""create host_with_bad_ssh_key table

Revision ID: ecd5f49567a6
Revises: 1dda1836ac55
Create Date: 2017-05-22 09:58:43.532714

"""
from sqlalchemy.dialects import postgresql
from alembic import op
import sqlalchemy as sa
import datetime


def _get_date():
    return datetime.datetime.now()


# revision identifiers, used by Alembic.
revision = 'ecd5f49567a6'
down_revision = '1dda1836ac55'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('hosts_with_bad_ssh_key',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('perception_product_uuid', postgresql.UUID, nullable=False),
                    sa.Column('ip_addr', postgresql.INET, unique=True, nullable=False),
                    sa.Column('created_at', sa.TIMESTAMP, default=_get_date))


def downgrade():
    op.drop_table('hosts_with_bad_ssh_key')
