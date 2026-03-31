'''
Marshalling is the process of turning an in-memory object into a format more suitable for storage/transmission, like raw bytes.

Demarshalling is the inverse - converting e.g. raw bytes sent over the internet into a more complex in-memory object.

This module defines the Marshmallow schemas for marshalling/demarshalling DTOs and domain objects.
'''

from marshmallow import Schema, fields
from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from sahara_shield.app.model.orm import User

class UserSchema(SQLAlchemyAutoSchema):
    '''
    Schema for User domain objects.
    '''

    class Meta:
        model = User
        include_fk = True
        load_instance = True
        transient = True
        
class UserPublicSchema(Schema):
    '''
    Schema for User DTO objects to be returned by public API.
    '''

    id = fields.Int(required=True)
    email = fields.Str(required=True)
    role = fields.Str(required=True)
    verified =  fields.Bool(required=True)
    created_at = fields.DateTime(required=True)
    updated_at = fields.DateTime(required=True)