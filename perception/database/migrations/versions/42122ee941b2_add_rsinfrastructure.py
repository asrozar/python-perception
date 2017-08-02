"""create rsinfrastructure

Revision ID: 42122ee941b2
Revises: 564cf69874b
Create Date: 2017-03-12 10:35:43.033119

"""

# revision identifiers, used by Alembic.
revision = '42122ee941b2'
down_revision = '564cf69874b'
branch_labels = None
depends_on = None

from sqlalchemy.dialects import postgresql
from alembic import op
import sqlalchemy as sa
import datetime


def _get_date():
    return datetime.datetime.now()


def upgrade():
    op.create_table('rsinfrastructure',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('perception_product_uuid', postgresql.UUID, nullable=False),
                    sa.Column('ip_addr', postgresql.INET, unique=True, nullable=False),
                    sa.Column('host_name', sa.Text),
                    sa.Column('svc_user_id', sa.Integer, sa.ForeignKey('svc_users.id')),
                    sa.Column('created_at', sa.TIMESTAMP, default=_get_date),
                    sa.Column('updated_at', sa.TIMESTAMP, default=_get_date))


def downgrade():
    op.drop_table('rsinfrastructure')
