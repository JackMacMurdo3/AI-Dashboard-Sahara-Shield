from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep
from sahara_shield.app.model.marshal import UserSchema

users_router = APIRouter(
    prefix='/users',
    tags=['users'],
)

@users_router.get('/me')
async def read_my_info(user:CurrentUserDep):
    user_info = UserSchema(load_instance=False, exclude=('password_hash',)).dump(user)
    return user_info
