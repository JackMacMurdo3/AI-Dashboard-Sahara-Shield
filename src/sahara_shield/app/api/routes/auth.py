from fastapi import APIRouter, Response, HTTPException, Cookie
from sahara_shield.app.api.deps import UserAuthServiceDep
from sahara_shield.app.core.config import app_settings

auth_router = APIRouter(
    prefix='/auth',
    tags=['auth'],
)

@auth_router.post('/login')
async def login(email:str, password:str, response:Response, user_auth_service:UserAuthServiceDep):
    try:
        user_id = await user_auth_service.authenticate(email, password)
    except Exception:
        raise HTTPException(status_code=401, detail='Invalid email or password')
    
    auth_session = await user_auth_service.create_auth_session(user_id, app_settings.AUTH_COOKIE_MAX_AGE, persist=True)
    await user_auth_service.save_changes()
    response.set_cookie(
        key=app_settings.AUTH_COOKIE_KEY,
        value=auth_session.id,
        max_age=app_settings.AUTH_COOKIE_MAX_AGE,
        expires=auth_session.expires_at,
        path='/', # see https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/02-Testing_for_Cookies_Attributes#:~:text=mydomain.com.-,Path%20Attribute,-The%20Path%20attribute
        httponly=True,
        secure=True
    )

    return {'message': f'Created authentication session for user {auth_session.user_id} at {auth_session.created_at}'}

@auth_router.post('/logout')
async def logout(response:Response, user_auth_service:UserAuthServiceDep, session_id:str=Cookie(default='')):
    _ = await user_auth_service.delete_auth_session_by_token(session_id)
    await user_auth_service.save_changes()

    response.delete_cookie(key=app_settings.AUTH_COOKIE_KEY, path='/', secure=True, httponly=True)

    return {'message': 'Logged out'}
