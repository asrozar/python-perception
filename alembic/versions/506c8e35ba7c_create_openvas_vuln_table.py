"""create openvas_vuln table

Revision ID: 506c8e35ba7c
Revises: 13b7c3d4c802
Create Date: 2017-07-21 12:19:35.711173

"""
from sqlalchemy.dialects import postgresql
from alembic import op
import sqlalchemy as sa
import datetime


def _get_date():
    return datetime.datetime.now()

# revision identifiers, used by Alembic.
revision = '506c8e35ba7c'
down_revision = '13b7c3d4c802'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('openvas_vulns',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('perception_product_uuid', postgresql.UUID, nullable=False),
                    sa.Column('ip_addr', postgresql.INET, unique=True, nullable=False),
                    sa.Column('created_at', sa.TIMESTAMP, default=_get_date))


def downgrade():
    op.drop_table('openvas_vulns')
