from fastapi import APIRouter, Response, Cookie
from sahara_shield.app.api.deps import AuthControllerDep

auth_router = APIRouter(
    prefix='/auth',
    tags=['auth'],
)

@auth_router.post('/login')
async def login(
    email: str,
    password: str,
    response: Response,
    controller: AuthControllerDep,
    ):
    '''
    Authenticate a user and create an authenticated session.
    '''
    return await controller.login(email, password, response)

@auth_router.post('/logout')
async def logout(
    response: Response,
    controller: AuthControllerDep,
    session_id: str = Cookie(default=''),
    ):
    '''
    Terminate the current user's authenticated session.
    '''
    return await controller.logout(session_id, response)

