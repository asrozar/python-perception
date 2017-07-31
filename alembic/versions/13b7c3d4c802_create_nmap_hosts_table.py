"""create nmap_hosts table

Revision ID: 13b7c3d4c802
Revises: ecd5f49567a6
Create Date: 2017-07-21 08:19:17.849112

"""
from sqlalchemy.dialects import postgresql
from alembic import op
import sqlalchemy as sa
from django.utils import timezone


def _get_date():
    return timezone.now()

# revision identifiers, used by Alembic.
revision = '13b7c3d4c802'
down_revision = 'ecd5f49567a6'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('nmap_hosts',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('perception_product_uuid', postgresql.UUID, nullable=False),
                    sa.Column('ip_addr', postgresql.INET, unique=True, nullable=False),
                    sa.Column('created_at', sa.TIMESTAMP, default=_get_date))


def downgrade():
    op.drop_table('nmap_hosts')
