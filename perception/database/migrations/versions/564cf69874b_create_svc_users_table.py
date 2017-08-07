"""create svc_users table

Revision ID: 564cf69874b
Revises: 
Create Date: 2015-06-23 16:45:18.964546

"""

# revision identifiers, used by Alembic.
revision = '564cf69874b'
down_revision = None
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql
import datetime


def _get_date():
    return datetime.datetime.now()


def upgrade():
    op.create_table('svc_users',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('perception_product_uuid', postgresql.UUID, nullable=False),
                    sa.Column('username', sa.String, nullable=False, unique=True),
                    sa.Column('description', sa.String),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=True), default=_get_date),
                    sa.Column('updated_at', sa.TIMESTAMP(timezone=True), default=_get_date)),


def downgrade():
    op.drop_table('svc_users')
