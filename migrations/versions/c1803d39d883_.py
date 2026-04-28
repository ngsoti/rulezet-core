"""empty message
Revision ID: c1803d39d883
Revises: 614a222a6f84
Create Date: 2026-04-28 09:27:24.584454
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

revision = 'c1803d39d883'
down_revision = '614a222a6f84'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    rule_columns = [col['name'] for col in inspector.get_columns('rule')]
    tag_columns = [col['name'] for col in inspector.get_columns('tag')]

    with op.batch_alter_table('rule', schema=None) as batch_op:
        if 'cve_id' in rule_columns:
            batch_op.alter_column('cve_id',
                existing_type=sa.TEXT(),
                type_=sa.String(),
                existing_nullable=True)

    with op.batch_alter_table('tag', schema=None) as batch_op:
        if 'galaxy_meta' not in tag_columns:
            batch_op.add_column(sa.Column('galaxy_meta', sa.JSON(), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    rule_columns = [col['name'] for col in inspector.get_columns('rule')]
    tag_columns = [col['name'] for col in inspector.get_columns('tag')]

    with op.batch_alter_table('tag', schema=None) as batch_op:
        if 'galaxy_meta' in tag_columns:
            batch_op.drop_column('galaxy_meta')

    with op.batch_alter_table('rule', schema=None) as batch_op:
        if 'cve_id' in rule_columns:
            batch_op.alter_column('cve_id',
                existing_type=sa.String(),
                type_=sa.TEXT(),
                existing_nullable=True)