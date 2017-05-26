"""create mac_vendors table

Revision ID: 42220a53132
Revises: 4fc9479a07
Create Date: 2015-06-23 16:30:39.218344

"""

# revision identifiers, used by Alembic.
revision = '42220a53132'
down_revision = '4fc9479a07'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa
import datetime


def _get_date():
    return datetime.datetime.now()


def upgrade():
    op.create_table('mac_vendors',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('name', sa.Text, unique=True, nullable=False),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=False), default=_get_date),
                    sa.Column('updated_at', sa.TIMESTAMP(timezone=False), onupdate=_get_date))


def downgrade():
    op.drop_table('mac_vendors')
