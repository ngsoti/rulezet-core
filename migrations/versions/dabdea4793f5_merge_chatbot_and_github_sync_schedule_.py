"""merge chatbot and github-sync-schedule migration branches

Revision ID: dabdea4793f5
Revises: cfc5e433271f, f6a9db782357
Create Date: 2026-07-23 09:40:45.330384

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dabdea4793f5'
down_revision = ('cfc5e433271f', 'f6a9db782357')
branch_labels = None
depends_on = None


def upgrade():
    pass


def downgrade():
    pass
