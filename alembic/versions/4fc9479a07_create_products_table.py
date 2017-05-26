"""create products table

Revision ID: 4fc9479a07
Revises: 4bbb8b6d5f6
Create Date: 2015-06-23 15:44:46.104824

"""

# revision identifiers, used by Alembic.
revision = '4fc9479a07'
down_revision = '4bbb8b6d5f6'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa
import datetime


def _get_date():
  return datetime.datetime.now()


def upgrade():
    op.create_table('products',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('cpe', sa.Text, nullable=False, unique=True),
                    sa.Column('product_type', sa.Text, nullable=False),
                    sa.Column('vendor_id', sa.Integer, sa.ForeignKey('vendors.id'), nullable=False),
                    sa.Column('name', sa.Text, nullable=False),
                    sa.Column('version', sa.Text),
                    sa.Column('product_update', sa.Text),
                    sa.Column('edition', sa.Text),
                    sa.Column('language', sa.Text),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=False), default=_get_date),
                    sa.Column('updated_at', sa.TIMESTAMP(timezone=False), onupdate=_get_date))


def downgrade():
    op.drop_table('products')
