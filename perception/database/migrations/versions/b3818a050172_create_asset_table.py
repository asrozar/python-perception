"""create asset table

Revision ID: b3818a050172
Revises: 506c8e35ba7c
Create Date: 2017-08-19 14:11:49.697305

"""
from sqlalchemy.dialects import postgresql
from alembic import op
import sqlalchemy as sa
import datetime


def _get_date():
    return datetime.datetime.now()

# revision identifiers, used by Alembic.
revision = 'b3818a050172'
down_revision = '506c8e35ba7c'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('assets',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('perception_product_uuid', postgresql.UUID, nullable=False),
                    sa.Column('ip_addr', postgresql.INET, unique=True, nullable=False),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=True), default=_get_date))


def downgrade():
    op.drop_table('assets')
