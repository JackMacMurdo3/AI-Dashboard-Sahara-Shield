'''
Commandline script to insert seed data (fake data) into the Sahara Shop database
'''

import asyncio
import argparse
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import insert, text
from argparse import Namespace
from sahara_shield.app.seed_data import generate_seed_users, generate_seed_protected_apps
from sahara_shield.app.model.marshal import UserSchema, ProtectedAppSchema
from sahara_shield.app.core.config import app_settings
from sahara_shield.app.model.orm import User, ProtectedApp

def make_args_parser():
    parser = argparse.ArgumentParser(
        prog='Sahara Shop Seed Data Script',
        description='Populates Sahara Shop database w/ seed data. Assumes necessary tables already exist, as created by e.g. Alembic.',
        add_help=True,
    )

    parser.add_argument(
        '--n-users',
        type=int,
        default=10,
        help='Number of users to generate',
    )

    parser.add_argument(
        '--n-protected-apps',
        type=int,
        default=10,
        help='Number of protected apps to generate',
    )

    parser.add_argument(
        '--seed',
        type=int,
        default=6424,
        help='Seed that controls randomly-generated values',
    )

    parser.add_argument(
        '--pretruncate-tables',
        action='store_true',
        help='If specified, truncate affected tables prior to inserting new seed data. WARNING: THIS WILL REMOVE DATA!!!',
    )

    return parser

async def insert_seed_data(
    n_users:int,
    n_protected_apps:int,
    pretruncate_tables:bool=False,
):
    users = generate_seed_users(n=n_users)
    user_dicts = UserSchema(load_instance=False).dump(users, many=True)

    protected_apps = generate_seed_protected_apps(n=n_protected_apps, users=users)
    protected_app_dicts = ProtectedAppSchema(load_instance=False).dump(protected_apps, many=True)

    engine = create_async_engine(
            app_settings.make_mysql_db_url(),
            echo=True,
        )

    async with engine.connect() as conn:
        if pretruncate_tables:
            # remove (truncate) data from tables before inserting new seed data
            # truncate is auto-committed so you can't undo it!!!
            # see https://stackoverflow.com/questions/5452760/how-to-truncate-a-foreign-key-constrained-table
            await conn.execute(text('SET FOREIGN_KEY_CHECKS = 0'))
            await conn.execute(text(f'TRUNCATE TABLE {User.__tablename__}'))
            await conn.execute(text(f'TRUNCATE TABLE {ProtectedApp.__tablename__}'))

        await conn.execute(insert(User), user_dicts)

        await conn.execute(insert(ProtectedApp), protected_app_dicts)

        await conn.commit()

    await engine.dispose()

async def main(args:Namespace):
    import factory.random
    import random
    # fix the randomness for reproducibility
    factory.random.reseed_random(args.seed)
    random.seed(args.seed)

    await insert_seed_data(
        args.n_users,
        args.n_protected_apps,
        pretruncate_tables=args.pretruncate_tables,
    )

if __name__ == '__main__':
    args = make_args_parser().parse_args()
    asyncio.run(main(args))