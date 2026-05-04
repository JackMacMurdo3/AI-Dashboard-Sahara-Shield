'''
All things related to generating fake/"seed" data to insert into database, primarily for testing/demonstration.

See https://stackoverflow.com/questions/19334604/creating-seed-data-in-a-flask-migrate-or-alembic-migration

See https://stackoverflow.com/questions/78493927/how-can-i-batch-create-a-sql-alchemy-model-using-factory-boy
'''

import factory
import factory.fuzzy
import json
import random
from datetime import datetime, timezone, timedelta
from faker import Faker
from factory.alchemy import SQLAlchemyModelFactory
from sahara_shield.app.model.orm import (
    User, ProtectedApp, AppSecurityPolicy, 
    FlaggedRequest, SecurityEvent,
)
from sahara_shield.app.core.security import password_sec_measure
from sahara_shield.app.model.enums import (
    HTTPMethods, PolicyModes, ThreatTypes, 
    ThreatSeverities, SecurityActions, RoutePatternDatatypes,
)

DEFAULT_PASSWORD = 'sahara123!'
fake = Faker()

def make_random_query_string() -> str | None:
    if random.randint(1, 4) == 1:
        return None

    params: dict[str, str] = {}
    for _ in range(random.randint(1, 4)):
        key = fake.word()
        value = random.choice([
            fake.word(),
            str(random.randint(1, 1000)),
            fake.uuid4(),
        ])
        params[key] = value

    return '&'.join(f'{key}={value}' for key, value in params.items())

def make_random_http_headers() -> dict[str, str] | None:
    if random.randint(1, 5) == 1:
        return None

    headers: dict[str, str] = {
        'User-Agent': fake.user_agent(),
        'Accept': random.choice([
            'application/json',
            'text/html',
            '*/*',
        ]),
    }

    if random.randint(1, 2) == 1:
        headers['Content-Type'] = random.choice([
            'application/json',
            'application/x-www-form-urlencoded',
            'text/plain',
        ])

    if random.randint(1, 3) == 1:
        headers['X-Request-Id'] = fake.uuid4()

    if random.randint(1, 3) == 1:
        headers['X-Forwarded-For'] = fake.ipv4_public()

    return headers

def make_random_http_body() -> str | None:
    if random.randint(1, 3) == 1:
        return None

    body_kind = random.choice(['json', 'text', 'form'])

    if body_kind == 'json':
        return json.dumps({
            fake.word(): fake.sentence(),
            fake.word(): random.randint(0, 1000),
            fake.word(): random.choice([True, False]),
        })

    if body_kind == 'form':
        return '&'.join([
            f'{fake.word()}={fake.word()}',
            f'{fake.word()}={random.randint(1, 100)}',
            f'{fake.word()}={fake.uuid4()}',
        ])

    return fake.paragraph()

class UserFactory(SQLAlchemyModelFactory):
    '''
    Factory for creating seed users.
    '''

    class Meta:
        model = User

    id = factory.Sequence(lambda n: n + 1)
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

    id = factory.Sequence(lambda n: n + 1)
    owner_user_id = factory.Faker('pyint', min_value=1)
    name = factory.Faker('domain_word')
    url = factory.LazyAttribute(lambda obj: f'http://{obj.name}.{fake.tld()}')
    live = factory.fuzzy.FuzzyChoice([True, False])
    risk_score_severity_score_weight = factory.LazyFunction(
        lambda: round(random.randint(0, 100) / 100, 2)
    )
    risk_score_confidence_pct_weight = factory.LazyAttribute(
        lambda obj: round(1 - obj.risk_score_severity_score_weight, 2)
    )
    created_at = factory.fuzzy.FuzzyDateTime(
        datetime(2022, 1, 1, tzinfo=timezone.utc), 
        end_dt=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    
class AppSecurityPolicyFactory(SQLAlchemyModelFactory):
    '''
    Factory for creating seed app security policies.
    '''

    class Meta:
        model = AppSecurityPolicy

    id = factory.Sequence(lambda n: n + 1)
    protected_app_id = factory.Faker('pyint', min_value=1)
    name = factory.LazyFunction(lambda: f'Policy #{random.randint(1, 1000)}')
    http_method = factory.fuzzy.FuzzyChoice(HTTPMethods)
    route_pattern = factory.LazyFunction(
        lambda: (
            f'/api/v{random.randint(1, 1000)}/'
            f'{fake.word()}/'
            '{'+f'{fake.word()}:{random.choice(list(RoutePatternDatatypes)).value}'+'}'
        )
    )
    mode = factory.fuzzy.FuzzyChoice(PolicyModes)
    active = factory.fuzzy.FuzzyChoice([True, False])
    priority = factory.Faker('pyint', min_value=0, max_value=100)
    action_score_threshold = factory.Faker('pyint', min_value=0, max_value=100)
    created_at = factory.fuzzy.FuzzyDateTime(
        datetime(2022, 1, 1, tzinfo=timezone.utc), 
        end_dt=datetime(2026, 1, 1, tzinfo=timezone.utc),
        )
    active_status_changed_at = factory.LazyAttribute(lambda obj: fake.date_time_between_dates(
        datetime_start=obj.created_at, 
        tzinfo=timezone.utc),
    )

class FlaggedRequestFactory(SQLAlchemyModelFactory):
    '''
    Factory for creating seed flagged requests.
    '''

    class Meta:
        model = FlaggedRequest

    id = factory.Sequence(lambda n: n + 1)
    app_security_policy_id = factory.Faker('pyint', min_value=1)
    observed_at = factory.fuzzy.FuzzyDateTime(
        datetime(2026, 1, 1, tzinfo=timezone.utc), 
        end_dt=datetime.now(tz=timezone.utc),
        )
    http_method = factory.fuzzy.FuzzyChoice(HTTPMethods)
    query_string = factory.LazyFunction(make_random_query_string)
    route_path = factory.LazyFunction(
        lambda: (
            f'{fake.url()}api/v{random.randint(1, 1000)}/'
            f'{fake.word()}/'
            f'{fake.word() if random.randint(1, 3) == 1 else random.randint(1, 1000)}'
        )
    )
    headers = factory.LazyFunction(make_random_http_headers)
    body = factory.LazyFunction(make_random_http_body)
    source_ip = factory.Faker('ipv4_public')
    created_at = factory.LazyAttribute(lambda obj: fake.date_time_between_dates(
        datetime_start=obj.observed_at, 
        datetime_end=obj.observed_at + timedelta(minutes=1), 
        tzinfo=timezone.utc),
    )

class SecurityEventFactory(SQLAlchemyModelFactory):
    '''
    Factory for creating seed security events.
    '''

    class Meta:
        model = SecurityEvent

    id = factory.Sequence(lambda n: n + 1)
    flagged_request_id = factory.Faker('pyint', min_value=1)
    threat_type = factory.fuzzy.FuzzyChoice(ThreatTypes)
    threat_severity = factory.fuzzy.FuzzyChoice(ThreatSeverities)
    confidence_pct = factory.Faker('pyint', min_value=0, max_value=100)
    risk_score = factory.Faker('pyint', min_value=0, max_value=100)
    action = factory.fuzzy.FuzzyChoice(SecurityActions)
    reason_desc = factory.LazyFunction(lambda: fake.sentence(nb_words=15))
    created_at = factory.fuzzy.FuzzyDateTime(
        datetime(2026, 1, 1, tzinfo=timezone.utc), 
        end_dt=datetime.now(tz=timezone.utc),
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

        # remove chosen protected app so it's not picked again
        unchosen_protected_apps = unchosen_protected_apps - set([protected_app])

    return protected_apps

def generate_seed_app_security_policies(n:int=10, protected_apps:list[ProtectedApp]=[]) -> list[AppSecurityPolicy]:
    app_security_policies: list[AppSecurityPolicy] = AppSecurityPolicyFactory.build_batch(n)

    if not protected_apps: return app_security_policies # no protected app objects provided, return app security policies as-is

    unchosen_app_security_policies = set(app_security_policies)
    while unchosen_app_security_policies:
        # randomly choose a protected app
        protected_app = random.choice(protected_apps)

        # randomly choose app security policy
        app_security_policy = random.choice(list(unchosen_app_security_policies))

        # associate app security policy w/ protected app
        app_security_policy.protected_app_id = protected_app.id

        # remove chosen app security policy so it's not picked again
        unchosen_app_security_policies = unchosen_app_security_policies - set([app_security_policy])

    return app_security_policies

def generate_seed_flagged_requests(n:int=10, app_security_policies:list[AppSecurityPolicy]=[]) -> list[FlaggedRequest]:
    '''
    Generates n seed flagged request instances.
    '''
    
    flagged_requests: list[FlaggedRequest] = FlaggedRequestFactory.build_batch(n)

    if not app_security_policies: return flagged_requests # no app security policy objects provided, return flagged requests as-is

    unchosen_flagged_requests = set(flagged_requests)
    while unchosen_flagged_requests:
        # randomly choose an app security policy
        app_security_policy = random.choice(app_security_policies)

        # randomly choose flagged request
        flagged_request = random.choice(list(unchosen_flagged_requests))

        # associate flagged request w/ app security policy
        flagged_request.app_security_policy_id = app_security_policy.id

        # remove chosen flagged request so it's not picked again
        unchosen_flagged_requests = unchosen_flagged_requests - set([flagged_request])

    return flagged_requests

def generate_seed_security_events(n:int=10, flagged_requests:list[FlaggedRequest]=[]) -> list[SecurityEvent]:
    if flagged_requests:
        # must maintain a 1:1 relationship between flagged requests and security events
        # if we're inserting into a database
        n = len(flagged_requests)

    security_events: list[SecurityEvent] = SecurityEventFactory.build_batch(n)

    if not flagged_requests: return security_events # no flagged request objects provided, return security events as-is

    unchosen_security_events = set(security_events)
    unchosen_flagged_requests = set(flagged_requests)
    while unchosen_security_events:
        # randomly choose a flagged request
        flagged_request = random.choice(list(unchosen_flagged_requests))

        # randomly choose security event
        security_event = random.choice(list(unchosen_security_events))

        # associate security event w/ flagged request
        security_event.flagged_request_id = flagged_request.id

        # remove chosen flagged request so it's not picked again
        unchosen_flagged_requests = unchosen_flagged_requests - set([flagged_request])

        # remove chosen security event so it's not picked again
        unchosen_security_events = unchosen_security_events - set([security_event])

    return security_events
