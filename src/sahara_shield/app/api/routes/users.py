from fastapi import APIRouter
from sahara_shield.app.api.deps import CurrentUserDep
from sahara_shield.app.model.marshal import UserSchema

users_router = APIRouter(
    prefix='/users',
    tags=['users'],
)

@users_router.get('/me')
async def read_current_user(user:CurrentUserDep):
    user_info = UserSchema(load_instance=False).dump(user)
    return user_info
