'''
All things related to generating fake/"seed" data to insert into database, primarily for testing/demonstration.

See https://stackoverflow.com/questions/19334604/creating-seed-data-in-a-flask-migrate-or-alembic-migration

See https://stackoverflow.com/questions/78493927/how-can-i-batch-create-a-sql-alchemy-model-using-factory-boy
'''

import factory
import factory.fuzzy
import random
from datetime import datetime, timezone, timedelta
from faker import Faker
from factory.alchemy import SQLAlchemyModelFactory
from sahara_shield.app.model.orm import User, ProtectedApp
from sahara_shield.app.core.security import password_sec_measure

DEFAULT_PASSWORD = 'sahara123!'
FILENAME_EXTENSIONS = ['js', 'py', 'html', 'css']
fake = Faker()

class UserFactory(SQLAlchemyModelFactory):
    '''
    Factory for creating seed users.
    '''

    class Meta:
        model = User

    id = factory.Faker('pyint', min_value=1)
    email = factory.LazyFunction(lambda: f"{fake.user_name()}@fakemail.com")
    password_hash = password_sec_measure.hash_password(DEFAULT_PASSWORD)
    verified = True
    created_at = factory.fuzzy.FuzzyDateTime(
        datetime(2022, 1, 1, tzinfo=timezone.utc), 
        end_dt=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    
class ProtectedAppFactory(SQLAlchemyModelFactory):
    '''
    Factory for creating seed protected apps.
    '''

    class Meta:
        model = ProtectedApp

    id = factory.Faker('pyint', min_value=1)
    owner_user_id = factory.Faker('pyint', min_value=1)
    name = factory.Faker('company')
    url = factory.LazyAttribute(lambda obj: f'http://{obj.name}.{fake.tld()}')
    live = factory.fuzzy.FuzzyChoice([True, False])
    created_at = factory.fuzzy.FuzzyDateTime(
        datetime(2022, 1, 1, tzinfo=timezone.utc), 
        end_dt=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    
def generate_seed_users(n:int=10) -> list[User]:
    '''
    Generates n seed user instances.

    Args:
        n (int): The number of user instances to generate.
    Returns:

        users (list): A list of n user instances.
    '''

    return UserFactory.build_batch(n)

def generate_seed_protected_apps(n:int=10, users:list[User]=[]) -> list[ProtectedApp]:
    protected_apps: list[ProtectedApp] = ProtectedAppFactory.build_batch(n)

    if not users: return protected_apps # no user objects provided, return protected apps as-is

    unchosen_protected_apps = set(protected_apps)
    while unchosen_protected_apps:
        # randomly choose a user
        user = random.choice(users)

        # randomly choose protected app
        protected_app = random.choice(list(unchosen_protected_apps))

        # associate user as owner of protected app
        protected_app.owner_user_id = user.id

        # remove chosen protectedapp so it's not picked again
        unchosen_protected_apps = unchosen_protected_apps - set([protected_app])

    return protected_apps
