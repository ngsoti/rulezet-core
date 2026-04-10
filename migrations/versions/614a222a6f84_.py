"""empty message
Revision ID: 614a222a6f84
Revises: c9c25261bb0b
Create Date: ...
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
from datetime import datetime, timezone

# revision identifiers, used by Alembic.
revision = '614a222a6f84'
down_revision = 'c9c25261bb0b'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    user_columns = [col['name'] for col in inspector.get_columns('user')]
    with op.batch_alter_table('user', schema=None) as batch_op:
        if 'is_verified' not in user_columns:
            batch_op.add_column(sa.Column('is_verified', sa.Boolean(), nullable=True))
        if 'verification_code' not in user_columns:
            batch_op.add_column(sa.Column('verification_code', sa.String(length=6), nullable=True))
        if 'verification_expiration' not in user_columns:
            batch_op.add_column(sa.Column('verification_expiration', sa.DateTime(), nullable=True))

    user_table = sa.sql.table('user',
        sa.sql.column('is_verified', sa.Boolean),
        sa.sql.column('verification_expiration', sa.DateTime)
    )
    op.execute(
        user_table.update().values(
            is_verified=True,
            verification_expiration=datetime.now(timezone.utc)
        )
    )


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    user_columns = [col['name'] for col in inspector.get_columns('user')]
    with op.batch_alter_table('user', schema=None) as batch_op:
        if 'verification_expiration' in user_columns:
            batch_op.drop_column('verification_expiration')
        if 'verification_code' in user_columns:
            batch_op.drop_column('verification_code')
        if 'is_verified' in user_columns:
            batch_op.drop_column('is_verified')