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
from sahara_shield.app.model.enums import UserRoles

@dataclass
class UserPublic():
    '''
    DTO for User instances to be returned by the public API.

    Schema for marshalling/demarshalling included. See https://pypi.org/project/marshmallow-dataclass/#:~:text=(Person)-,%40dataclass%20shortcut,-marshmallow_dataclass%20provides%20a
    '''

    Schema: ClassVar[Type[Schema]]
    id: int
    email: str
    role: UserRoles
    verified: bool
    scans_count: int
    files_scanned_count: int
    clean_files_count: int
    bad_files_count: int
    created_at: datetime
    updated_at: datetime
