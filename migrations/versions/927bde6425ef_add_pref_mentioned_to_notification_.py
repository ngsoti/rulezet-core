"""add pref_mentioned to notification_preference

Revision ID: 927bde6425ef
Revises: a2e06215ff88
Create Date: 2026-09-03 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = '927bde6425ef'
down_revision = 'a2e06215ff88'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    columns = [col['name'] for col in inspector.get_columns('notification_preference')]

    with op.batch_alter_table('notification_preference', schema=None) as batch_op:
        if 'pref_mentioned' not in columns:
            batch_op.add_column(sa.Column('pref_mentioned', sa.Boolean(), nullable=False, server_default=sa.true()))


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    columns = [col['name'] for col in inspector.get_columns('notification_preference')]

    with op.batch_alter_table('notification_preference', schema=None) as batch_op:
        if 'pref_mentioned' in columns:
            batch_op.drop_column('pref_mentioned')
