from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep
from sahara_shield.app.model.marshal import UserSchema
from sahara_shield.app.model.dto import UserPublic

users_router = APIRouter(
    prefix='/users',
    tags=['users'],
)

@users_router.get('/me')
async def read_current_user(user:CurrentUserDep):
    user_info = UserSchema(load_instance=False).dump(user)
    user_pub_info = UserPublic.Schema().load(user_info, unknown='exclude')
    return user_pub_info
