"""se agrego llave foranea en modelo user-> roles, se agrego el campo email -> unique=true

Revision ID: a5cd24aa86bf
Revises: c9b739d4165f
Create Date: 2022-09-03 10:00:49.351010

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'a5cd24aa86bf'
down_revision = 'c9b739d4165f'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_foreign_key(None, 'users', 'roles', ['rol_id'], ['id'])
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint(None, 'users', type_='foreignkey')
    # ### end Alembic commands ###
