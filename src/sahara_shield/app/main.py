from fastapi import FastAPI, responses, staticfiles
from pathlib import Path
from sahara_shield.app.core.config import app_settings
from sahara_shield.app.api.main import api_router
from sahara_shield.app.api.deps import (
    CurrentUserDep,
    ProtectedAppControllerDep,
    AppSecurityPolicyControllerDep,
)

app = FastAPI()
app.include_router(api_router, prefix=app_settings.API_STR_PREFIX)
BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / 'static'

# see https://fastapi.tiangolo.com/tutorial/static-files/
# see https://stackoverflow.com/a/70632774
app.mount(
    '/static',
    staticfiles.StaticFiles(directory=str(STATIC_DIR)),
    name='static',
)

@app.get('/', response_class=responses.FileResponse)
def root(user:CurrentUserDep):
    '''
    API route to fetch landing page HTML (aka the dashboard)

    Protected route - user must be logged in to access
    '''

    return responses.FileResponse(str(STATIC_DIR / 'html/index.html'))

@app.get('/login', response_class=responses.FileResponse)
def login_page():
    '''
    API route to fetch login page HTML
    '''

    return responses.FileResponse(str(STATIC_DIR / 'html/login.html'))

@app.get('/dashboard/', response_class=responses.FileResponse)
def dashboard_home_page(user:CurrentUserDep):
    '''
    API route to fetch protected app dashboard home (landing) page HTML

    Protected route - user must be logged in to access
    '''

    return responses.FileResponse(str(STATIC_DIR / 'html/dashboard.html'))

@app.get('/dashboard/{protected_app_id}', response_class=responses.FileResponse)
async def dashboard_protected_app_page(
    user: CurrentUserDep,
    protected_app_id: int,
    protected_app_controller: ProtectedAppControllerDep,
):
    '''
    API route to fetch protected app dashboard page HTML.
    '''

    # validate protected app existence/owernship
    await protected_app_controller.get_user_protected_app_by_id(user, protected_app_id)

    return responses.FileResponse(str(STATIC_DIR / 'html/dashboard.html'))

@app.get('/dashboard/{protected_app_id}/policies/{policy_id}', response_class=responses.FileResponse)
async def dashboard_protected_app_policy_page(
    user:CurrentUserDep,
    protected_app_id:int,
    policy_id:int,
    protected_app_controller: ProtectedAppControllerDep,
    policy_controller: AppSecurityPolicyControllerDep,
):
    '''
    API route to fetch a dedicated app security policy detail page HTML.
    '''

    # validate protected app and app security policy existence/ownership
    await protected_app_controller.get_user_protected_app_by_id(user, protected_app_id)
    await policy_controller.get_user_app_security_policy_by_id(user, policy_id)

    return responses.FileResponse(str(STATIC_DIR / 'html/policy_detail.html'))
