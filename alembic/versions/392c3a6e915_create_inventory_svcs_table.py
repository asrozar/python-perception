"""create inventory_svcs table

Revision ID: 392c3a6e915
Revises: 4e9f83654af,
Create Date: 2015-06-23 17:10:25.451434

"""

# revision identifiers, used by Alembic.
revision = '392c3a6e915'
down_revision = '4e9f83654af'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa
import datetime


def _get_date():
    return datetime.datetime.now()


def upgrade():
    op.create_table('inventory_svcs',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('inventory_host_id', sa.Integer, sa.ForeignKey('inventory_hosts.id', ondelete='cascade')),
                    sa.Column('protocol', sa.Text),
                    sa.Column('portid', sa.Integer),
                    sa.Column('name', sa.Text),
                    sa.Column('svc_product', sa.Text),
                    sa.Column('extra_info', sa.Text),
                    sa.Column('product_id', sa.Integer, sa.ForeignKey('products.id')),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=False), default=_get_date),
                    sa.Column('updated_at', sa.TIMESTAMP(timezone=False), onupdate=_get_date))


def downgrade():
    op.drop_table('inventory_svcs')
