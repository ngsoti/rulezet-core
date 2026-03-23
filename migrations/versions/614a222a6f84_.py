from alembic import op
import sqlalchemy as sa
from datetime import datetime, timezone

# revision identifiers, used by Alembic.
revision = '614a222a6f84'
down_revision = 'c9c25261bb0b'
branch_labels = None
depends_on = None

def upgrade():
    # 1. Add columns (allowing nullable=True first to avoid errors with existing data)
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('is_verified', sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column('verification_code', sa.String(length=6), nullable=True))
        batch_op.add_column(sa.Column('verification_expiration', sa.DateTime(), nullable=True))

    # 2. Define a temporary table reference for the update
    user_table = sa.sql.table('user',
        sa.sql.column('is_verified', sa.Boolean),
        sa.sql.column('verification_expiration', sa.DateTime)
    )

    # 3. Update existing rows: Set is_verified to True and expiration to now
    op.execute(
        user_table.update().values(
            is_verified=True,
            verification_expiration=datetime.now(timezone.utc)
        )
    )

def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_column('verification_expiration')
        batch_op.drop_column('verification_code')
        batch_op.drop_column('is_verified')