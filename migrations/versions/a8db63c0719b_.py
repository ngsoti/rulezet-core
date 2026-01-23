from alembic import op
import sqlalchemy as sa
import uuid # Import nécessaire pour générer les UUID

# revision identifiers, used by Alembic.
revision = 'a8db63c0719b'
down_revision = '98d339abb265'
branch_labels = None
depends_on = None

def upgrade():
    # 1. Création des colonnes (nullable=True pour l'instant pour ne pas bloquer)
    with op.batch_alter_table('bundle', schema=None) as batch_op:
        batch_op.add_column(sa.Column('uuid', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('created_by', sa.String(length=255), nullable=True))
        batch_op.add_column(sa.Column('view_count', sa.Integer(), server_default='0', nullable=False))
        batch_op.add_column(sa.Column('download_count', sa.Integer(), server_default='0', nullable=False))
        batch_op.add_column(sa.Column('is_verified', sa.Boolean(), server_default='0', nullable=False))

    # 2. Migration des données existantes
    bundle_table = sa.table('bundle',
        sa.column('id', sa.Integer),
        sa.column('uuid', sa.String),
        sa.column('created_by', sa.String)
    )

    connection = op.get_bind()
    
    # On récupère tous les bundles qui n'ont pas encore d'UUID
    results = connection.execute(sa.select(bundle_table.c.id)).fetchall()
    
    for row in results:
        new_uuid = str(uuid.uuid4())
        connection.execute(
            bundle_table.update().where(bundle_table.c.id == row[0]).values(
                uuid=new_uuid,
                created_by='user'
            )
        )

    # 3. Maintenant que tout est rempli, on impose les contraintes de non-nullité et l'index
    with op.batch_alter_table('bundle', schema=None) as batch_op:
        batch_op.alter_column('uuid', nullable=False)
        batch_op.alter_column('created_by', nullable=False)
        batch_op.create_index(batch_op.f('ix_bundle_uuid'), ['uuid'], unique=True)

def downgrade():
    with op.batch_alter_table('bundle', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_bundle_uuid'))
        batch_op.drop_column('is_verified')
        batch_op.drop_column('download_count')
        batch_op.drop_column('view_count')
        batch_op.drop_column('created_by')
        batch_op.drop_column('uuid')