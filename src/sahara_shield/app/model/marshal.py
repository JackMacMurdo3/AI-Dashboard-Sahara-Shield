'''
Marshalling is the process of turning an in-memory object into a format more suitable for storage/transmission, like raw bytes.

Demarshalling is the inverse - converting e.g. raw bytes sent over the internet into a more complex in-memory object.

This module defines the Marshmallow schemas for marshalling/demarshalling domain objects.
'''

from marshmallow_sqlalchemy import SQLAlchemyAutoSchema
from sahara_shield.app.model.orm import User, Scan, Evidence

class UserSchema(SQLAlchemyAutoSchema):
    '''
    Schema for User domain objects.
    '''

    class Meta:
        model = User
        include_fk = True
        load_instance = True
        transient = True
        
class ScanSchema(SQLAlchemyAutoSchema):
    '''
    Schema for Scan domain objects.
    '''

    class Meta:
        model = Scan
        include_fk = True
        load_instance = True
        transient = True

class EvidenceSchema(SQLAlchemyAutoSchema):
    '''
    Scehma for Evidence domain objects.
    '''
    
    class Meta:
        model = Evidence
        include_fk = True
        load_instance = True
        transient = True
        