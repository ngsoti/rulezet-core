"""add vulnerability_identifiers with default empty list

Revision ID: 67d889c747bf
Revises: 0419cbf0f1fa
Create Date: 2026-02-04 07:29:27.194693

"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '67d889c747bf'
down_revision = '0419cbf0f1fa'
branch_labels = None
depends_on = None


def upgrade():
    op.add_column('bundle', sa.Column('vulnerability_identifiers', sa.Text(), nullable=True))

    op.execute("UPDATE bundle SET vulnerability_identifiers = '[]' WHERE vulnerability_identifiers IS NULL")

    with op.batch_alter_table('bundle', schema=None) as batch_op:
        batch_op.alter_column('vulnerability_identifiers',
               existing_type=sa.Text(),
               nullable=False,
               server_default='[]')


def downgrade():
    with op.batch_alter_table('bundle', schema=None) as batch_op:
        batch_op.drop_column('vulnerability_identifiers')