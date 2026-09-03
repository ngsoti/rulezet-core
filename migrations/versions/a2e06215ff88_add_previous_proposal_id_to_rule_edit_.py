"""add previous_proposal_id to rule_edit_proposal

Revision ID: a2e06215ff88
Revises: e862097a8d21
Create Date: 2026-09-03 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect

# revision identifiers, used by Alembic.
revision = 'a2e06215ff88'
down_revision = 'e862097a8d21'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    columns = [col['name'] for col in inspector.get_columns('rule_edit_proposal')]

    with op.batch_alter_table('rule_edit_proposal', schema=None) as batch_op:
        if 'previous_proposal_id' not in columns:
            batch_op.add_column(sa.Column('previous_proposal_id', sa.Integer(), nullable=True))
        if not any(fk for fk in inspector.get_foreign_keys('rule_edit_proposal')
                   if fk.get('referred_table') == 'rule_edit_proposal'
                   and 'previous_proposal_id' in fk.get('constrained_columns', [])):
            batch_op.create_foreign_key(None, 'rule_edit_proposal', ['previous_proposal_id'], ['id'])


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    columns = [col['name'] for col in inspector.get_columns('rule_edit_proposal')]

    with op.batch_alter_table('rule_edit_proposal', schema=None) as batch_op:
        fk_to_drop = next((fk for fk in inspector.get_foreign_keys('rule_edit_proposal')
                           if fk.get('referred_table') == 'rule_edit_proposal'
                           and 'previous_proposal_id' in fk.get('constrained_columns', [])), None)
        if fk_to_drop:
            batch_op.drop_constraint(fk_to_drop['name'], type_='foreignkey')
        if 'previous_proposal_id' in columns:
            batch_op.drop_column('previous_proposal_id')
