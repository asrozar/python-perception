"""create seed_routers table

Revision ID: 17edc14f5f2
Revises: e1955a32f1
Create Date: 2015-10-25 14:21:59.829937

"""

# revision identifiers, used by Alembic.
revision = '17edc14f5f2'
down_revision = 'e1955a32f1'
branch_labels = None
depends_on = None

from sqlalchemy.dialects import postgresql
from alembic import op
import sqlalchemy as sa
import datetime


def _get_date():
    return datetime.datetime.now()


def upgrade():
    op.create_table('seed_routers',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('perception_product_uuid', postgresql.UUID, nullable=False),
                    sa.Column('ip_addr', postgresql.INET, unique=True, nullable=False),
                    sa.Column('host_name', sa.Text),
                    sa.Column('svc_user_id', sa.Integer, sa.ForeignKey('svc_users.id', ondelete='cascade')),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=True), default=_get_date))


def downgrade():
    op.drop_table('seed_routers')
