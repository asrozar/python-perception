"""create rsaddrs table

Revision ID: 65df8acfcffc
Revises: 4e051e1c257
Create Date: 2017-04-16 13:42:28.371479

"""
from sqlalchemy.dialects import postgresql
from alembic import op
import sqlalchemy as sa
import datetime

# revision identifiers, used by Alembic.
revision = '65df8acfcffc'
down_revision = '4e051e1c257'
branch_labels = None
depends_on = None


def _get_date():
    return datetime.datetime.now()


def upgrade():
    op.create_table('rsaddrs',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('perception_product_uuid', postgresql.UUID, nullable=False),
                    sa.Column('rsinfrastructure_id', sa.Integer, sa.ForeignKey('rsinfrastructure.id'), nullable=False),
                    sa.Column('ip_addr', postgresql.INET),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=True), default=_get_date),
                    sa.Column('updated_at', sa.TIMESTAMP(timezone=True), default=_get_date))


def downgrade():
    op.drop_table('rsaddrs')
