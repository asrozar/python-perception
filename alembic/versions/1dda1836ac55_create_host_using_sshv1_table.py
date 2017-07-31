"""create host_using_sshv1 table

Revision ID: 1dda1836ac55
Revises: 3132f6875d83
Create Date: 2017-05-22 09:58:07.585231

"""
from sqlalchemy.dialects import postgresql
from alembic import op
import sqlalchemy as sa
import datetime


def _get_date():
    return datetime.datetime.now()


# revision identifiers, used by Alembic.
revision = '1dda1836ac55'
down_revision = '3132f6875d83'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('hosts_using_sshv1',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('perception_product_uuid', postgresql.UUID, nullable=False),
                    sa.Column('ip_addr', postgresql.INET, unique=True, nullable=False),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=False), default=_get_date))


def downgrade():
    op.drop_table('hosts_using_sshv1')
