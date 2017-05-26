"""create local_subnets tables

Revision ID: 8851295f5e81
Revises: 65df8acfcffc
Create Date: 2017-04-28 10:38:19.439848

"""
from alembic import op
from sqlalchemy.dialects import postgresql
import sqlalchemy as sa
import datetime


def _get_date():
  return datetime.datetime.now()

# revision identifiers, used by Alembic.
revision = '8851295f5e81'
down_revision = '65df8acfcffc'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('local_subnets',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('subnet', postgresql.INET, nullable=False),
                    sa.Column('rsinfrastructure_id', sa.Integer, sa.ForeignKey('rsinfrastructure.id'), nullable=False),
                    sa.Column('source_int', sa.Text),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=False), default=_get_date))


def downgrade():
    op.drop_table('local_subnets')
