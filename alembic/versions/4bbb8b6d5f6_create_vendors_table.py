"""create vendors table

Revision ID: 4bbb8b6d5f6
Revises: 
Create Date: 2015-06-23 15:42:53.247610

"""

# revision identifiers, used by Alembic.
revision = '4bbb8b6d5f6'
down_revision = None
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa
import datetime


def _get_date():
    return datetime.datetime.now()


def upgrade():
    op.create_table('vendors',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('name', sa.Text, unique=True, nullable=False),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=False), default=_get_date),
                    sa.Column('updated_at', sa.TIMESTAMP(timezone=False), onupdate=_get_date))


def downgrade():
    op.drop_table('vendors')
