from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from sqlalchemy import select, text
from app.core.config import get_settings
from app.core.security import password_hasher
from app.database.session import SessionLocal
from app.models.entities import User
from app.schemas.inputs import Registration
from app.detection.rules import sync_rules
from app.api import auth, routes


@asynccontextmanager
async def lifespan(app):
    settings = get_settings()
    with SessionLocal() as db:
        sync_rules(db)
        if settings.bootstrap_admin_email and settings.bootstrap_admin_password:
            details = Registration(email=settings.bootstrap_admin_email, password=settings.bootstrap_admin_password, name='SOC Administrator')
            if not db.scalar(select(User).where(User.email == details.email)):
                db.add(User(email=details.email, name=details.name, password_hash=password_hasher.hash(details.password), role='admin'))
                db.commit()
    yield


app = FastAPI(title='SentinelAI', description='Defensive security operations and explainable threat detection.', version='1.0.0', lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=get_settings().cors_origins.split(','), allow_credentials=True, allow_methods=['GET','POST','PATCH'], allow_headers=['Authorization','Content-Type','X-Ingest-Key'])


class BodyLimitMiddleware:
    def __init__(self, app, limit=2_000_000):
        self.app, self.limit = app, limit

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        # Buffer a bounded body before parsing, including chunked requests.
        chunks, size = [], 0
        while True:
            message = await receive()
            if message['type'] == 'http.disconnect':
                return
            size += len(message.get('body', b''))
            if size > self.limit:
                return await JSONResponse({'detail':'Request body exceeds 2 MB'},status_code=413)(scope, receive, send)
            chunks.append(message.get('body',b''))
            if not message.get('more_body', False):
                break
        consumed = False
        async def bounded_receive():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {'type':'http.request','body':b''.join(chunks),'more_body':False}
            return await receive()
        await self.app(scope, bounded_receive, send)


app.add_middleware(BodyLimitMiddleware)


@app.middleware('http')
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update({'X-Content-Type-Options':'nosniff','X-Frame-Options':'DENY','Referrer-Policy':'no-referrer','Cache-Control':'no-store'})
    if get_settings().environment == 'production':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, error: RequestValidationError):
    # Pydantic's default response can include submitted passwords or raw log data.
    return JSONResponse(status_code=422, content={'detail':[{'loc':list(e['loc']), 'msg':e['msg'], 'type':e['type']} for e in error.errors()]})


@app.exception_handler(Exception)
async def unexpected_error(request: Request, error: Exception):
    logging.getLogger('sentinelai').error('Request failed: %s', type(error).__name__)
    return JSONResponse(status_code=500, content={'detail':'An internal error occurred'})


@app.get('/api/health', tags=['Health'])
def health():
    with SessionLocal() as db:
        db.execute(text('SELECT 1'))
    return {'status':'ok','service':'SentinelAI'}


app.include_router(auth.router, prefix='/api')
app.include_router(routes.router, prefix='/api')
