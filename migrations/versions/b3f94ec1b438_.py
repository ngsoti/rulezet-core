"""empty message

Revision ID: b3f94ec1b438
Revises: e59277710971
Create Date: 2026-02-03 07:57:14.435689

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'b3f94ec1b438'
down_revision = 'e59277710971'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('comment_bundle', sa.Column('active', sa.Boolean(), nullable=False, server_default=sa.text('true')))
    try:
        with op.batch_alter_table('comment_bundle', schema=None) as batch_op:
            batch_op.drop_index('ix_comment_bundle_active')
    except Exception:
        pass


def downgrade():
    with op.batch_alter_table('comment_bundle', schema=None) as batch_op:
        batch_op.drop_column('active')