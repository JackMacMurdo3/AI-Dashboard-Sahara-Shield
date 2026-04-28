'''
Marshalling is the process of turning an in-memory object into a format more suitable for storage/transmission, like raw bytes.

Demarshalling is the inverse - converting e.g. raw bytes sent over the internet into a more complex in-memory object.

This module defines the Marshmallow schemas for marshalling/demarshalling domain objects.
'''

from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from sahara_shield.app.model.orm import User, ProtectedApp, AppSecurityPolicy

class UserSchema(SQLAlchemyAutoSchema):
    '''
    Schema for User domain objects.
    '''

    class Meta:
        model = User
        include_fk = True
        load_instance = True
        transient = True
        

class ProtectedAppSchema(SQLAlchemyAutoSchema):
    class Meta:
        model = ProtectedApp
        include_fk = True
        load_instance = True
        transient = True

class AppSecurityPolicySchema(SQLAlchemyAutoSchema):
    class Meta:
        model = AppSecurityPolicy
        include_fk = True
        load_instance = True
        transient = True
        