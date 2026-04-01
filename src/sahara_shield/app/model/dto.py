'''
Data Transfer Objects (DTOs) act as higher-level wrappers over domain objects, enabling exposure of different data
depending on the object's destination (e.g. public API). 
They are meant to be simple and "dumb", in that they are merely data containers - no business logic methods.

This module defines the marshmallow dataclasses and schemas for marshalling/demarshalling DTOs.
'''

from marshmallow_dataclass import dataclass
from typing import ClassVar, Type
from marshmallow import Schema
from datetime import datetime
from sahara_shield.app.model.enums import UserRole

@dataclass
class UserPublic():
    '''
    DTO for User instances to be returned by the public API.

    Schema included. See https://pypi.org/project/marshmallow-dataclass/#:~:text=(Person)-,%40dataclass%20shortcut,-marshmallow_dataclass%20provides%20a
    '''

    Schema: ClassVar[Type[Schema]]
    id: int
    email: str
    role: UserRole
    verified: bool
    created_at: datetime
    updated_at: datetime
