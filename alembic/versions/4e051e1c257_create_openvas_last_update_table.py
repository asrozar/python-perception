"""create openvas last update table

Revision ID: 4e051e1c257
Revises: 46942860847
Create Date: 2016-01-04 09:04:30.597267

"""

# revision identifiers, used by Alembic.
revision = '4e051e1c257'
down_revision = '46942860847'
branch_labels = None
depends_on = None

from sqlalchemy.dialects import postgresql
from alembic import op
import sqlalchemy as sa
import datetime


def _get_date():
    return datetime.datetime.now()


def upgrade():
    op.create_table('openvas_last_updates',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('perception_product_uuid', postgresql.UUID, nullable=False),
                    sa.Column('updated_at', sa.TIMESTAMP(timezone=False), onupdate=_get_date))


def downgrade():
    op.drop_table('openvas_last_updates')
