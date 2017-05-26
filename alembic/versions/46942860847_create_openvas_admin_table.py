"""create openvas admin table

Revision ID: 46942860847
Revises: 17edc14f5f2
Create Date: 2015-12-14 08:12:27.329203

"""

# revision identifiers, used by Alembic.
revision = '46942860847'
down_revision = '17edc14f5f2'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa
import datetime
from sqlalchemy.dialects import postgresql


def _get_date():
    return datetime.datetime.now()


def upgrade():
    op.create_table('openvas_admin',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('username', sa.Text, nullable=False, unique=True),
                    sa.Column('password', postgresql.UUID, nullable=False),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=False), default=_get_date),
                    sa.Column('updated_at', sa.TIMESTAMP(timezone=False), onupdate=_get_date))


def downgrade():
  op.drop_table('openvas_admin')
