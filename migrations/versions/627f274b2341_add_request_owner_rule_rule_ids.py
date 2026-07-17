"""add request_owner_rule rule_ids

Revision ID: 627f274b2341
Revises: dd693f3dcefc
Create Date: 2026-07-17
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = '627f274b2341'
down_revision = 'dd693f3dcefc'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    cols = {c['name'] for c in inspector.get_columns('request_owner_rule')}
    if 'rule_ids' not in cols:
        with op.batch_alter_table('request_owner_rule', schema=None) as batch_op:
            batch_op.add_column(sa.Column('rule_ids', sa.JSON(), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    cols = {c['name'] for c in inspector.get_columns('request_owner_rule')}
    if 'rule_ids' in cols:
        with op.batch_alter_table('request_owner_rule', schema=None) as batch_op:
            batch_op.drop_column('rule_ids')
