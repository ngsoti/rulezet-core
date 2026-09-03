"""add meta to ai_generation

Revision ID: a9d81d8324b2
Revises: 927bde6425ef
Create Date: 2026-09-03 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = 'a9d81d8324b2'
down_revision = '927bde6425ef'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    columns = [col['name'] for col in inspector.get_columns('ai_generation')]

    with op.batch_alter_table('ai_generation', schema=None) as batch_op:
        if 'meta' not in columns:
            batch_op.add_column(sa.Column('meta', sa.JSON(), nullable=True))


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    columns = [col['name'] for col in inspector.get_columns('ai_generation')]

    with op.batch_alter_table('ai_generation', schema=None) as batch_op:
        if 'meta' in columns:
            batch_op.drop_column('meta')
