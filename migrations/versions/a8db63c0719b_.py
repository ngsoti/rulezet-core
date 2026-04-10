"""empty message
Revision ID: a8db63c0719b
Revises: 98d339abb265
Create Date: ...
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy import inspect
import uuid

# revision identifiers, used by Alembic.
revision = 'a8db63c0719b'
down_revision = '98d339abb265'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    bundle_columns = [col['name'] for col in inspector.get_columns('bundle')]

    with op.batch_alter_table('bundle', schema=None) as batch_op:
        if 'uuid' not in bundle_columns:
            batch_op.add_column(sa.Column('uuid', sa.String(length=255), nullable=True))
        if 'created_by' not in bundle_columns:
            batch_op.add_column(sa.Column('created_by', sa.String(length=255), nullable=True))
        if 'view_count' not in bundle_columns:
            batch_op.add_column(sa.Column('view_count', sa.Integer(), server_default='0', nullable=False))
        if 'download_count' not in bundle_columns:
            batch_op.add_column(sa.Column('download_count', sa.Integer(), server_default='0', nullable=False))
        if 'is_verified' not in bundle_columns:
            batch_op.add_column(sa.Column('is_verified', sa.Boolean(), server_default='0', nullable=False))

    bundle_table = sa.table('bundle',
        sa.column('id', sa.Integer),
        sa.column('uuid', sa.String),
        sa.column('created_by', sa.String)
    )

    results = bind.execute(sa.select(bundle_table.c.id)).fetchall()
    for row in results:
        new_uuid = str(uuid.uuid4())
        bind.execute(
            bundle_table.update().where(bundle_table.c.id == row[0]).values(
                uuid=new_uuid,
                created_by='user'
            )
        )

    existing_indexes = [ix['name'] for ix in inspector.get_indexes('bundle')]
    with op.batch_alter_table('bundle', schema=None) as batch_op:
        batch_op.alter_column('uuid', nullable=False)
        batch_op.alter_column('created_by', nullable=False)
        if 'ix_bundle_uuid' not in existing_indexes:
            batch_op.create_index(batch_op.f('ix_bundle_uuid'), ['uuid'], unique=True)


def downgrade():
    bind = op.get_bind()
    inspector = inspect(bind)

    bundle_columns = [col['name'] for col in inspector.get_columns('bundle')]
    existing_indexes = [ix['name'] for ix in inspector.get_indexes('bundle')]

    with op.batch_alter_table('bundle', schema=None) as batch_op:
        if 'ix_bundle_uuid' in existing_indexes:
            batch_op.drop_index(batch_op.f('ix_bundle_uuid'))
        if 'is_verified' in bundle_columns:
            batch_op.drop_column('is_verified')
        if 'download_count' in bundle_columns:
            batch_op.drop_column('download_count')
        if 'view_count' in bundle_columns:
            batch_op.drop_column('view_count')
        if 'created_by' in bundle_columns:
            batch_op.drop_column('created_by')
        if 'uuid' in bundle_columns:
            batch_op.drop_column('uuid')