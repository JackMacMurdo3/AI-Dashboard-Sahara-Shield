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
from sahara_shield.app.model.orm import User, Scan, Evidence
from sahara_shield.app.model.enums import EvidenceThreatTypes, EvidenceSeverities
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

class ScanFactory(SQLAlchemyModelFactory):
    '''
    Factory for creating seed security scans.
    '''

    class Meta:
        model = Scan

    id = factory.Faker('pyint', min_value=1)
    user_id = factory.Faker('pyint', min_value=1)
    repository_url = factory.LazyFunction(lambda: f"https://github.com/{fake.user_name()}/{fake.catch_phrase()}.git")
    started_at = factory.fuzzy.FuzzyDateTime(
        datetime(2022, 1, 1, tzinfo=timezone.utc), 
        end_dt=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    finished_at = factory.LazyAttribute(lambda obj: fake.date_time_between_dates(
        datetime_start=obj.started_at, 
        datetime_end=obj.started_at + timedelta(days=1), # scans end at most 1 day after being started for example
        tzinfo=timezone.utc),
        )
    created_at = factory.fuzzy.FuzzyDateTime(
        datetime(2022, 1, 1, tzinfo=timezone.utc), 
        end_dt=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    
class EvidenceFactory(SQLAlchemyModelFactory):
    '''
    Factory for creating seed evidence.
    '''

    class Meta:
        model = Evidence

    id = factory.Faker('pyint', min_value=1)
    scan_id = factory.Faker('pyint', min_value=1)
    filename = factory.LazyFunction(
        lambda: fake.file_path(
            depth=random.randint(1, 3), 
            absolute=False, 
            extension=FILENAME_EXTENSIONS)
            )
    threat_type = factory.fuzzy.FuzzyChoice(EvidenceThreatTypes)
    confidence_level = factory.Faker('pyint', min_value=0, max_value=100)
    severity = factory.fuzzy.FuzzyChoice(EvidenceSeverities)

def generate_seed_users(n:int=10) -> list[User]:
    '''
    Generates n seed user instances.

    Args:
        n (int): The number of user instances to generate.
    Returns:

        users (list): A list of n user instances.
    '''

    return UserFactory.build_batch(n)

def generate_seed_scans(n:int=10, users:list[User]=[]) -> list[Scan]:
    '''
    Generates n seed scan instances.

    Args:
        n (int): The number of scan instances to generate.
    Returns:
        scans (list): A list of n scan instances
    '''

    scans: list[Scan] = ScanFactory.build_batch(n)

    if not users: return scans # no user objects provided, return scans as-is

    unchosen_scans = set(scans)
    while unchosen_scans:
        # randomly choose a user
        user = random.choice(users)

        # randomly choose scan
        scan = random.choice(list(unchosen_scans))

        # associate user as initiator of scan
        scan.user_id = user.id

        # remove chosen scan so it's not picked again
        unchosen_scans = unchosen_scans - set([scan])

    return scans

def generate_seed_evidence(n:int=10, scans:list[Scan]=[]) -> list[Evidence]:
    all_evidence: list[Evidence] = EvidenceFactory.build_batch(n)

    if not scans: return all_evidence # no scan objects provided, return evidence as-is

    unchosen_evidence: set[Evidence] = set(all_evidence)
    while unchosen_evidence:
        # randomly choose a scan
        scan = random.choice(scans)

        # randomly choose evidence
        evidence = random.choice(list(unchosen_evidence))

        # associate evidence to scan
        evidence.scan_id = scan.id

        # remove chosen evidence so it's not picked again
        unchosen_evidence = unchosen_evidence - set([evidence])

    return all_evidence
