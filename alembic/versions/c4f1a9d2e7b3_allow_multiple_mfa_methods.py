"""move mfa methods to user_mfa_methods (one row per enabled method)

Revision ID: c4f1a9d2e7b3
Revises: 86d3bd627838
Create Date: 2026-11-05 10:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'c4f1a9d2e7b3'
down_revision: Union[str, Sequence[str], None] = '86d3bd627838'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


mfa_method_enum = sa.Enum('TOTP', 'EMAIL', 'SMS', 'NONE', name='mfa_method_enum')


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'user_mfa_methods',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        # Plain VARCHAR, no CHECK: a new method needs no migration.
        sa.Column('method', sa.String(length=20), nullable=False),
        sa.Column('secret', sa.String(length=255), nullable=True),
        sa.Column('last_used_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.Column('updated_at', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('user_id', 'method', name='uq_user_mfa_methods_user_method'),
    )
    op.create_index('ix_user_mfa_methods_user_id', 'user_mfa_methods', ['user_id'])

    # Carry over existing confirmed setups (dev data).
    op.execute(
        "INSERT INTO user_mfa_methods (id, user_id, method, secret) "
        "SELECT gen_random_uuid(), id, lower(mfa_method::text), "
        "CASE WHEN mfa_method = 'TOTP' THEN mfa_secret END "
        "FROM users WHERE mfa_enabled AND mfa_method IN ('TOTP', 'EMAIL')"
    )

    op.drop_column('users', 'mfa_enabled')
    op.drop_column('users', 'mfa_method')
    op.drop_column('users', 'mfa_secret')
    mfa_method_enum.drop(op.get_bind(), checkfirst=True)


def downgrade() -> None:
    """Downgrade schema. Users with both methods keep only TOTP."""
    mfa_method_enum.create(op.get_bind(), checkfirst=True)
    op.add_column('users', sa.Column('mfa_secret', sa.String(length=255), nullable=True))
    op.add_column('users', sa.Column('mfa_method', mfa_method_enum, nullable=True))
    op.add_column('users', sa.Column('mfa_enabled', sa.Boolean(), server_default=sa.false(), nullable=False))

    op.execute(
        "UPDATE users u SET mfa_enabled = true, "
        "mfa_method = upper(m.method)::mfa_method_enum, mfa_secret = m.secret "
        "FROM (SELECT DISTINCT ON (user_id) user_id, method, secret "
        "      FROM user_mfa_methods WHERE method IN ('totp', 'email') "
        "      ORDER BY user_id, method = 'totp' DESC) m "
        "WHERE u.id = m.user_id"
    )

    op.drop_index('ix_user_mfa_methods_user_id', table_name='user_mfa_methods')
    op.drop_table('user_mfa_methods')
