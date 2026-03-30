from fastapi import FastAPI, responses, staticfiles
from sahara_shield.app.core.config import app_settings
from sahara_shield.app.api.main import api_router

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
def root():
    '''
    API route to fetch landing page HTML
    '''

    return responses.FileResponse('./static/html/index.html')
