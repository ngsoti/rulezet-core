"""merge divergent heads, add config_type to field_parser_config

Revision ID: bae6d35e98f0
Revises: 665dddd355d8, cfc5e433271f, f6a9db782357
Create Date: 2026-08-07

The repo had accumulated three divergent migration heads (665dddd355d8,
cfc5e433271f, f6a9db782357 — each the tip of a different feature branch merged
into main without an Alembic merge in between). This migration reconciles them
into a single head, and piggybacks the field_parser_config.config_type column
needed to let it store both the base field-parser configs and the new
platform-tag-pattern configs.
"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'bae6d35e98f0'
down_revision = ('665dddd355d8', 'cfc5e433271f', 'f6a9db782357')
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('field_parser_config', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            'config_type', sa.String(length=50), nullable=False,
            server_default='field_parser',
        ))


def downgrade():
    with op.batch_alter_table('field_parser_config', schema=None) as batch_op:
        batch_op.drop_column('config_type')
