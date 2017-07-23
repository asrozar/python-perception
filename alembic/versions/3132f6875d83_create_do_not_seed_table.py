"""create do_not_seeds table

Revision ID: 3132f6875d83
Revises: 65df8acfcffc
Create Date: 2017-05-18 11:00:29.781865

"""
from sqlalchemy.dialects import postgresql
from alembic import op
import sqlalchemy as sa
import datetime


def _get_date():
    return datetime.datetime.now()


# revision identifiers, used by Alembic.
revision = '3132f6875d83'
down_revision = '65df8acfcffc'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('do_not_seeds',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('perception_product_uuid', postgresql.UUID, nullable=False),
                    sa.Column('ip_addr', postgresql.INET, unique=True, nullable=False),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=False), default=_get_date))


def downgrade():
    op.drop_table('do_not_seeds')
