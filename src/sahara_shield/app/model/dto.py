'''
Data Transfer Objects (DTOs) act as higher-level wrappers over domain objects, enabling exposure of different data
depending on the object's destination (e.g. public API).

They are meant to be simple and "dumb", in that they are merely data containers - no business logic methods.
'''

from dataclasses import dataclass
from datetime import datetime
from sahara_shield.app.model.enums import UserRole

@dataclass(slots=True)
class UserPublic():
    '''
    DTO for User instances to be returned by the public API.
    '''

    id: int
    email: str
    role: UserRole
    verified: bool
    created_at: datetime
    updated_at: datetime
