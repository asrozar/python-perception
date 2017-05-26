"""create table vulnerabilities

Revision ID: 7c34e9a89bc0
Revises: 8851295f5e81
Create Date: 2016-06-29 10:11:36.057723

"""

# revision identifiers, used by Alembic.
revision = '7c34e9a89bc0'
down_revision = '8851295f5e81'
branch_labels = None
depends_on = None

from alembic import op
import sqlalchemy as sa
import datetime


def _get_date():
  return datetime.datetime.now()


def upgrade():
    op.create_table('vulnerabilities',
                    sa.Column('id', sa.Integer, primary_key=True, nullable=False),
                    sa.Column('name', sa.Text, nullable=False),
                    sa.Column('cvss_score', sa.Float, nullable=False),
                    sa.Column('bug_id', sa.Text),
                    sa.Column('family', sa.Text),
                    sa.Column('cve_id', sa.Text),
                    sa.Column('inventory_host_id', sa.Integer, sa.ForeignKey('inventory_hosts.id', ondelete='cascade')),
                    sa.Column('port', sa.Text),
                    sa.Column('threat_score', sa.Text),
                    sa.Column('severity_score', sa.Float),
                    sa.Column('xrefs', sa.Text),
                    sa.Column('tags', sa.Text),
                    sa.Column('validated', sa.BOOLEAN),
                    sa.Column('created_at', sa.TIMESTAMP(timezone=False), default=_get_date))


def downgrade():
    op.drop_table('vulnerabilities')
