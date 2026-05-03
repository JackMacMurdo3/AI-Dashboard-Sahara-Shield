"""add decision engine key to app security policies

Revision ID: 7a9d2f4c6e31
Revises: 2ec144d59e61
Create Date: 2026-05-02 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '7a9d2f4c6e31'
down_revision: Union[str, Sequence[str], None] = '2ec144d59e61'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column(
        'app_security_policies',
        sa.Column(
            'decision_engine_key',
            sa.Enum('RANDOM', 'AI', name='decisionenginekeys'),
            nullable=False,
            server_default='RANDOM',
        ),
    )


def downgrade() -> None:
    op.drop_column('app_security_policies', 'decision_engine_key')