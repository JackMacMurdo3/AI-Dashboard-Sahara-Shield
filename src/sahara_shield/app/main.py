from fastapi import FastAPI, responses, staticfiles
from sahara_shield.app.core.config import app_settings
from sahara_shield.app.api.main import api_router
from sahara_shield.app.api.deps import CurrentUserDep

app = FastAPI()
app.include_router(api_router, prefix=app_settings.API_STR_PREFIX)

# see https://fastapi.tiangolo.com/tutorial/static-files/
# see https://stackoverflow.com/a/70632774
app.mount(
    '/static',
    staticfiles.StaticFiles(directory='./static'),
    name='static',
)

@app.get('/', response_class=responses.FileResponse)
def root(user:CurrentUserDep):
    '''
    API route to fetch landing page HTML (aka the dashboard)

    Protected route - user must be logged in to access
    '''

    return responses.FileResponse('./static/html/index.html')

@app.get('/login', response_class=responses.FileResponse)
def login_page():
    '''
    API route to fetch login page HTML
    '''

    return responses.FileResponse('./static/html/login.html')

@app.get('/dashboard/', response_class=responses.FileResponse)
@app.get('/dashboard/{protected_app_id}', response_class=responses.FileResponse)
def dashboard_home_page(user:CurrentUserDep, protected_app_id:int):
    '''
    API route to fetch protected app dashboard home (landing) page HTML

    Protected route - user must be logged in to access
    '''

    return responses.FileResponse('./static/html/dashboard.html')
