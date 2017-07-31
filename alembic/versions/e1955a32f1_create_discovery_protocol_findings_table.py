"""create discovery_protocol_findings table

Revision ID: e1955a32f1
Revises: 42122ee941b2
Create Date: 2015-06-25 13:00:36.962406

"""

# revision identifiers, used by Alembic.
revision = 'e1955a32f1'
down_revision = '42122ee941b2'
branch_labels = None
depends_on = None

from alembic import op
from sqlalchemy.dialects import postgresql
import sqlalchemy as sa
from django.utils import timezone


def _get_date():
  return timezone.now()


def upgrade():
    op.create_table('discovery_protocol_findings',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('perception_product_uuid', postgresql.UUID, nullable=False),
                    sa.Column('rsinfrastructure_id', sa.Integer, sa.ForeignKey('rsinfrastructure.id'), nullable=False),
                    sa.Column('ip_addr', postgresql.INET),
                    sa.Column('platform', sa.Text),
                    sa.Column('capabilities', sa.Text),
                    sa.Column('created_at', sa.TIMESTAMP, default=_get_date))


def downgrade():
  op.drop_table('discovery_protocol_findings')
