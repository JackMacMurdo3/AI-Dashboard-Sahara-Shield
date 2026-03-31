'''
All things related to generating fake/"seed" data to insert into database.

See https://stackoverflow.com/questions/19334604/creating-seed-data-in-a-flask-migrate-or-alembic-migration

See https://stackoverflow.com/questions/78493927/how-can-i-batch-create-a-sql-alchemy-model-using-factory-boy
'''

import factory
import factory.fuzzy
from datetime import datetime, timezone
from faker import Faker
from sahara_shield.app.model.orm import User
from sahara_shield.app.core.security import password_sec_measure

DEFAULT_PASSWORD = 'sahara123!'
fake = Faker()

class UserFactory(factory.alchemy.SQLAlchemyModelFactory):
    '''
    Factory for creating users of Sahara Shop.
    '''

    class Meta:
        model = User

    id = factory.Faker('pyint', min_value=1)
    email = factory.LazyFunction(lambda: f"{fake.user_name()}@fakemail.com")
    password_hash = password_sec_measure.hash_password(DEFAULT_PASSWORD)
    verified = True
    created_at = factory.fuzzy.FuzzyDateTime(datetime(2022, 1, 1, tzinfo=timezone.utc), end_dt=datetime(2026, 1, 1, tzinfo=timezone.utc))

def generate_seed_users(n:int=10) -> list[User]:
    '''
    Generates n seed user instances.

    Args:
        n (int): The number of user instances to generate.
    Returns:

        list (list): A list of n user instances.
    '''

    return UserFactory.build_batch(n)