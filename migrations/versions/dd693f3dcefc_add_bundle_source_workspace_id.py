"""add bundle source_workspace_id

Revision ID: dd693f3dcefc
Revises: 84fa91f73d5a
Create Date: 2026-07-16
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = 'dd693f3dcefc'
down_revision = '84fa91f73d5a'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    bundle_cols = {c['name'] for c in inspector.get_columns('bundle')}
    if 'source_workspace_id' not in bundle_cols:
        with op.batch_alter_table('bundle', schema=None) as batch_op:
            batch_op.add_column(sa.Column('source_workspace_id', sa.Integer(), nullable=True))
            batch_op.create_index('ix_bundle_source_workspace_id', ['source_workspace_id'], unique=False)
            batch_op.create_foreign_key(
                'fk_bundle_source_workspace_id', 'workspace', ['source_workspace_id'], ['id'], ondelete='SET NULL'
            )


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)
    bundle_cols = {c['name'] for c in inspector.get_columns('bundle')}
    if 'source_workspace_id' in bundle_cols:
        with op.batch_alter_table('bundle', schema=None) as batch_op:
            batch_op.drop_constraint('fk_bundle_source_workspace_id', type_='foreignkey')
            batch_op.drop_index('ix_bundle_source_workspace_id')
            batch_op.drop_column('source_workspace_id')
