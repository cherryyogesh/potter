"""Potter 2: local-first privacy-gated voice assistant backend.

Deploy behind a trusted HTTPS reverse proxy with POTTER_SECURE_COOKIES=1.
Voice biometrics and always-on device hotwords are NOT claimed by this module.
"""
from __future__ import annotations

import ast
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import httpx
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator

ROOT = Path(__file__).resolve().parent
DATA = Path(os.getenv('POTTER_DATA_DIR', str(ROOT / 'data')))
DATA.mkdir(parents=True, exist_ok=True)
DB = DATA / 'potter.sqlite3'
STATIC = ROOT / 'static'
OLLAMA_BASE = os.getenv('POTTER_OLLAMA_URL', 'http://127.0.0.1:11434')
OLLAMA_CHAT_URL = OLLAMA_BASE.rstrip('/') + '/api/chat'
OLLAMA_TAGS_URL = OLLAMA_BASE.rstrip('/') + '/api/tags'
OLLAMA_PULL_URL = OLLAMA_BASE.rstrip('/') + '/api/pull'
OLLAMA_MODEL = os.getenv('POTTER_OLLAMA_MODEL', 'llama3.2:3b')

# Free LLM models to offer — lightweight models that run well locally
FREE_MODELS = [
    {'id': 'llama3.2:3b', 'name': 'Llama 3.2 3B', 'size': '~2GB', 'desc': 'Meta\'s compact model — fast and capable'},
    {'id': 'llama3.2:1b', 'name': 'Llama 3.2 1B', 'size': '~1.3GB', 'desc': 'Ultra-light Llama — fastest response'},
    {'id': 'qwen3:4b', 'name': 'Qwen 3 4B', 'size': '~2.6GB', 'desc': 'Alibaba\'s efficient multilingual model'},
    {'id': 'gemma3:4b', 'name': 'Gemma 3 4B', 'size': '~3GB', 'desc': 'Google\'s open model — strong reasoning'},
    {'id': 'phi4-mini:3.8b', 'name': 'Phi-4 Mini 3.8B', 'size': '~2.4GB', 'desc': 'Microsoft\'s small powerhouse'},
    {'id': 'mistral:7b', 'name': 'Mistral 7B', 'size': '~4.1GB', 'desc': 'Mistral AI — great all-rounder'},
    {'id': 'deepseek-r1:7b', 'name': 'DeepSeek R1 7B', 'size': '~4.7GB', 'desc': 'DeepSeek reasoning model'},
]

# Active model (mutable at runtime)
_active_model = OLLAMA_MODEL
SECURE_COOKIES = os.getenv('POTTER_SECURE_COOKIES', '0') == '1'
TIMEZONE = os.getenv('POTTER_TIMEZONE', 'Asia/Kolkata')
try:
    TZ = ZoneInfo(TIMEZONE)
except ZoneInfoNotFoundError:
    TZ = timezone.utc

app = FastAPI(title='Potter Local AI', version='2.0.0')
app.mount('/static', StaticFiles(directory=STATIC), name='static')
_LOCK = threading.RLock()
# Token stores only an opaque fingerprint; sessions never reveal their tokens to JavaScript.
SESSIONS: dict[str, float] = {}
ATTEMPTS: dict[str, list[float]] = {}
SESSION_SECONDS = 8 * 60 * 60


def now():
    return datetime.now(timezone.utc)


def connection():
    db = sqlite3.connect(DB, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA busy_timeout=10000')
    return db


def setup_db():
    with connection() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS config (k TEXT PRIMARY KEY, v TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY, owner TEXT NOT NULL, body TEXT NOT NULL, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS reminders (id INTEGER PRIMARY KEY, owner TEXT NOT NULL, body TEXT NOT NULL, due TEXT, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS guests (id INTEGER PRIMARY KEY, name TEXT UNIQUE NOT NULL, consent INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS tasks (id INTEGER PRIMARY KEY, owner TEXT NOT NULL, body TEXT NOT NULL, done INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS conversation_log (id INTEGER PRIMARY KEY, role TEXT NOT NULL, agent TEXT NOT NULL, content TEXT NOT NULL, created TEXT NOT NULL);
        ''')
        cols = [r['name'] for r in db.execute('PRAGMA table_info(reminders)')]
        if 'delivered' not in cols:
            db.execute('ALTER TABLE reminders ADD COLUMN delivered INTEGER NOT NULL DEFAULT 0')

setup_db()


def cfg(key):
    with connection() as db:
        row = db.execute('SELECT v FROM config WHERE k=?', (key,)).fetchone()
        return row['v'] if row else None


def set_cfg(key, value):
    with connection() as db:
        db.execute('INSERT OR REPLACE INTO config(k,v) VALUES(?,?)', (key, value))


def hash_pin(pin):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac('sha256', pin.encode(), salt, 360000)
    return f'{salt.hex()}:{digest.hex()}'


def verify_pin(pin, encoded):
    try:
        salt, expected = encoded.split(':')
        return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',pin.encode(),bytes.fromhex(salt),360000).hex(),expected)
    except (ValueError, AttributeError):
        return False


def token_hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def is_boss(req: Request):
    token = req.cookies.get('potter_session', '')
    if not token:
        return False
    key = token_hash(token)
    with _LOCK:
        expiry = SESSIONS.get(key, 0)
        if expiry and expiry <= time.time():
            SESSIONS.pop(key, None)
    return expiry > time.time()


def require_boss(req):
    if not is_boss(req):
        raise HTTPException(403, 'Boss authentication required. Voice alone does not unlock private data.')


def issue_session(response):
    token = secrets.token_urlsafe(40)
    with _LOCK:
        SESSIONS[token_hash(token)] = time.time() + SESSION_SECONDS
    response.set_cookie('potter_session', token, max_age=SESSION_SECONDS,
                        httponly=True, samesite='strict', secure=SECURE_COOKIES, path='/')


def rate_limited(req):
    key = req.client.host if req.client else 'unknown'
    stamp = time.monotonic()
    with _LOCK:
        attempts = [x for x in ATTEMPTS.get(key, []) if stamp-x<900]
        if len(attempts) >= 8:
            raise HTTPException(429, 'Too many login attempts. Try again later.')
        attempts.append(stamp)
        ATTEMPTS[key] = attempts


@app.middleware('http')
async def protect_unsafe_methods(req: Request, call_next):
    # Same-origin CSRF protection for cookie authentication; do not allow wildcard CORS.
    if req.method in ('POST','PATCH','PUT','DELETE'):
        origin = req.headers.get('origin')
        if origin:
            from urllib.parse import urlsplit
            origin_url = urlsplit(origin)
            host = req.headers.get('host', '')
            if origin_url.netloc != host or origin_url.scheme not in ('http','https'):
                return Response('Cross-origin write rejected', status_code=403)
    return await call_next(req)


class PIN(BaseModel):
    pin: str = Field(min_length=8, max_length=128)

class Message(BaseModel):
    text: str = Field(min_length=1, max_length=3000)

class Note(BaseModel):
    text: str = Field(min_length=1, max_length=4000)

class Reminder(BaseModel):
    text: str = Field(min_length=1, max_length=2000)
    due: datetime
    @field_validator('due')
    @classmethod
    def timezone_required(cls, value):
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('Supply a timezone-aware ISO datetime')
        return value

class Guest(BaseModel):
    name: str = Field(min_length=1, max_length=60)
    consent: bool
    @field_validator('name')
    @classmethod
    def trim(cls, value):
        if not value.strip(): raise ValueError('Name is required')
        return value.strip()

class Task(BaseModel):
    text: str = Field(min_length=1, max_length=2000)

class TaskUpdate(BaseModel):
    done: bool

@app.get('/')
def home(): return FileResponse(STATIC/'index.html')

@app.get('/api/health')
def health(): return {'status':'ok','app':'Potter','version':'2.0.0'}

@app.get('/api/status')
def status(req: Request):
    return {'configured': bool(cfg('pin')), 'role':'boss' if is_boss(req) else 'guest',
            'voice_identity':'not_available', 'model': _active_model,
            'hands_free':'foreground_browser_only', 'timezone': TIMEZONE}

@app.post('/api/setup')
def setup(body: PIN, req: Request, response: Response):
    rate_limited(req)
    with _LOCK:
        # First-time setup must be performed locally; do not allow unauthenticated network claiming.
        host = req.client.host if req.client else ''
        try: local = ipaddress.ip_address(host).is_loopback
        except ValueError: local = host in ('localhost','testclient')
        if not local and not os.getenv('POTTER_ALLOW_REMOTE_SETUP') == '1':
            raise HTTPException(403,'First-time setup is allowed only from the host computer')
        with connection() as db:
            result = db.execute('INSERT OR IGNORE INTO config(k,v) VALUES(?,?)',('pin',hash_pin(body.pin)))
            if result.rowcount != 1: raise HTTPException(409,'Already configured')
        issue_session(response)
    return {'role':'boss'}

@app.post('/api/login')
def login(body: PIN, req: Request, response: Response):
    rate_limited(req)
    encoded = cfg('pin')
    if not encoded or not verify_pin(body.pin, encoded):
        raise HTTPException(401, 'Invalid PIN')
    with _LOCK:
        ATTEMPTS.pop(req.client.host if req.client else 'unknown', None)
    issue_session(response)
    return {'role':'boss'}

@app.post('/api/logout')
def logout(req: Request, response: Response):
    token = req.cookies.get('potter_session','')
    with _LOCK:
        SESSIONS.pop(token_hash(token),None)
    response.delete_cookie('potter_session', path='/')
    return {'role':'guest'}

@app.get('/api/notes')
def notes(req: Request):
    require_boss(req)
    with connection() as db:
        return [dict(x) for x in db.execute('SELECT * FROM notes WHERE owner=? ORDER BY id DESC',('boss',))]

@app.post('/api/notes')
def create_note(req: Request, body: Note):
    require_boss(req)
    with connection() as db:
        cur=db.execute('INSERT INTO notes(owner,body,created) VALUES(?,?,?)',('boss',body.text,now().isoformat()))
        return {'id':cur.lastrowid,'ok':True}

@app.delete('/api/notes/{note_id}')
def delete_note(note_id: int, req: Request):
    require_boss(req)
    with connection() as db:
        changed=db.execute('DELETE FROM notes WHERE id=? AND owner=?',(note_id,'boss')).rowcount
    if not changed: raise HTTPException(404, 'Note not found')
    return {'deleted': True}

@app.get('/api/reminders')
def reminders(req: Request):
    require_boss(req)
    with connection() as db:
        return [dict(x) for x in db.execute('SELECT * FROM reminders WHERE owner=? ORDER BY due ASC',('boss',))]

@app.post('/api/reminders')
def create_reminder(req: Request, body: Reminder):
    require_boss(req)
    due=body.due.astimezone(timezone.utc)
    if due <= now(): raise HTTPException(422,'Reminder time must be in the future')
    with connection() as db:
        cur=db.execute('INSERT INTO reminders(owner,body,due,created) VALUES(?,?,?,?)',('boss',body.text,due.isoformat(),now().isoformat()))
        return {'id':cur.lastrowid,'ok':True,'notice':'Stored. Foreground notification polling only; no OS-level alarm guarantee.'}

@app.delete('/api/reminders/{reminder_id}')
def delete_reminder(reminder_id:int,req: Request):
    require_boss(req)
    with connection() as db:
        changed=db.execute('DELETE FROM reminders WHERE id=? AND owner=?',(reminder_id,'boss')).rowcount
    if not changed: raise HTTPException(404,'Reminder not found')
    return {'deleted':True}

@app.get('/api/reminders/due')
def due_reminders(req: Request):
    require_boss(req)
    # Atomically claim reminders to avoid duplicates across polling clients.
    with connection() as db:
        results=[dict(x) for x in db.execute('SELECT * FROM reminders WHERE owner=? AND delivered=0 AND due<=? ORDER BY due LIMIT 40',('boss',now().isoformat()))]
        if results:
            db.executemany('UPDATE reminders SET delivered=1 WHERE id=?', [(r['id'],) for r in results])
    return results

@app.get('/api/tasks')
def tasks(req:Request):
    require_boss(req)
    with connection() as db:
        return [dict(x) for x in db.execute('SELECT * FROM tasks WHERE owner=? ORDER BY done ASC,id DESC',('boss',))]

@app.post('/api/tasks')
def create_task(req:Request,body:Task):
    require_boss(req)
    with connection() as db:
        cur=db.execute('INSERT INTO tasks(owner,body,created) VALUES(?,?,?)',('boss',body.text,now().isoformat()))
        return {'id':cur.lastrowid,'ok':True}

@app.patch('/api/tasks/{task_id}')
def update_task(task_id:int,req:Request,body:TaskUpdate):
    require_boss(req)
    with connection() as db:
        changed=db.execute('UPDATE tasks SET done=? WHERE id=? AND owner=?',(int(body.done),task_id,'boss')).rowcount
    if not changed: raise HTTPException(404,'Task not found')
    return {'ok':True}

@app.delete('/api/tasks/{task_id}')
def delete_task(task_id:int,req:Request):
    require_boss(req)
    with connection() as db:
        changed=db.execute('DELETE FROM tasks WHERE id=? AND owner=?',(task_id,'boss')).rowcount
    if not changed: raise HTTPException(404,'Task not found')
    return {'deleted':True}

@app.get('/api/guests')
def guests(req:Request):
    require_boss(req)
    with connection() as db:
        return [dict(x) for x in db.execute('SELECT * FROM guests ORDER BY name')]

@app.post('/api/guests')
def create_guest(req:Request,body:Guest):
    require_boss(req)
    if not body.consent: raise HTTPException(400,'Guest consent is required')
    with connection() as db:
        db.execute('INSERT OR IGNORE INTO guests(name,consent) VALUES(?,1)',(body.name,))
    return {'saved':True,'voice_enrollment':'not_implemented'}

@app.delete('/api/guests/{guest_id}')
def remove_guest(guest_id:int, req:Request):
    require_boss(req)
    with connection() as db:
        changed=db.execute('DELETE FROM guests WHERE id=?',(guest_id,)).rowcount
    if not changed: raise HTTPException(404,'Guest not found')
    return {'deleted':True}


# ── Ollama model management ──────────────────────────────────────

class ModelSelect(BaseModel):
    model: str = Field(min_length=1, max_length=100)

@app.get('/api/ollama/status')
async def ollama_status():
    """Check if Ollama is reachable and list locally available models."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(OLLAMA_TAGS_URL)
            resp.raise_for_status()
            data = resp.json()
            installed = [m['name'] for m in data.get('models', [])]
            return {'online': True, 'installed': installed, 'active': _active_model,
                    'catalog': FREE_MODELS}
    except (httpx.HTTPError, KeyError, ValueError):
        return {'online': False, 'installed': [], 'active': _active_model,
                'catalog': FREE_MODELS}

@app.post('/api/ollama/pull')
async def ollama_pull(body: ModelSelect, req: Request):
    """Pull/download a model from Ollama registry."""
    require_boss(req)
    model_id = body.model
    # Validate against catalog
    valid_ids = {m['id'] for m in FREE_MODELS}
    if model_id not in valid_ids:
        raise HTTPException(400, f'Model {model_id} is not in the approved catalog')
    try:
        async with httpx.AsyncClient(timeout=600) as client:
            resp = await client.post(OLLAMA_PULL_URL, json={'name': model_id, 'stream': False})
            resp.raise_for_status()
            return {'ok': True, 'model': model_id, 'status': 'pulled'}
    except httpx.HTTPError as e:
        raise HTTPException(502, f'Failed to pull model: {e}')

@app.post('/api/ollama/select')
async def ollama_select(body: ModelSelect, req: Request):
    """Switch the active conversational model."""
    require_boss(req)
    global _active_model
    _active_model = body.model
    return {'ok': True, 'active': _active_model}

@app.get('/api/ollama/models')
async def ollama_models():
    """Return the catalog of recommended free models."""
    return {'catalog': FREE_MODELS, 'active': _active_model}


def safe_math(expression):
    if len(expression)>100: raise ValueError('Expression too long')
    tree=ast.parse(expression, mode='eval')
    def solve(n,depth=0):
        if depth>15: raise ValueError('Expression too complex')
        if isinstance(n,ast.Constant) and type(n.value) in (int,float):
            if abs(n.value)>1e12:raise ValueError('Number too large')
            return n.value
        if isinstance(n,ast.UnaryOp) and isinstance(n.op,(ast.UAdd,ast.USub)):
            v=solve(n.operand,depth+1)
            return v if isinstance(n.op,ast.UAdd) else -v
        if isinstance(n,ast.BinOp) and isinstance(n.op,(ast.Add,ast.Sub,ast.Mult,ast.Div)):
            a,b=solve(n.left,depth+1),solve(n.right,depth+1)
            if isinstance(n.op,ast.Add): result=a+b
            elif isinstance(n.op,ast.Sub):result=a-b
            elif isinstance(n.op,ast.Mult):result=a*b
            else:result=a/b
            if abs(result)>1e12:raise ValueError('Result too large')
            return result
        raise ValueError('Unsupported expression')
    return solve(tree.body)


def agent_reply(agent,reply):
    return {'agent':agent,'reply':str(reply)}

@app.get('/api/agents')
def agents():
    return {'agents':[
        {'id':'privacy','name':'Privacy Guard','available':True,'description':'Enforces Boss-only private data access'},
        {'id':'calculator','name':'Calculator','available':True,'description':'Safe offline arithmetic'},
        {'id':'clock','name':'Clock','available':True,'description':'Local timezone, date and time'},
        {'id':'tasks','name':'Tasks & Reminders','available':True,'description':'Private reminders, notes, and to-dos'},
        {'id':'profiles','name':'Guest Profiles','available':True,'description':'Consent-based guest name registry; not voice recognition'},
        {'id':'conversation','name':'Local Conversation','available':True,'description':f'Ollama LLM — active model: {_active_model}'},
        {'id':'models','name':'Model Manager','available':True,'description':'Switch between free local LLMs (Llama, Qwen, Gemma, Phi, Mistral, DeepSeek)'},
        {'id':'weather','name':'Weather','available':False,'description':'Requires a weather provider and location configuration'},
        {'id':'speaker','name':'Voice Identity','available':False,'description':'Real speaker verification requires enrollment and calibrated models'},
        {'id':'realtime','name':'Realtime Voice','available':False,'description':'Hugging Face speech-to-speech backend not connected yet'}]}

@app.post('/api/chat')
async def chat(req:Request,body:Message):
    msg=body.text.strip(); low=msg.lower()
    boss=is_boss(req)
    # Restrict requests even if wording is indirect. No private tools are supplied to LLM.
    private_words=('my photos','my images','my messages','my files','my contacts','private notes','read my notes','my reminders','my tasks','show my notes','show my reminders','show my tasks','boss notes','boss messages','boss files','boss photos')
    if not boss and any(w in low for w in private_words):
        return agent_reply('privacy','That information belongs to Boss and requires authentication.')
    if low.startswith(('calculate ','what is ','what\'s ')):
        expression = re.sub(r'^(calculate |what is |what\'s )','',low).rstrip(' ?=')
        if re.fullmatch(r'[0-9.\s+*/()\-]+',expression) and any(c in expression for c in '+-*/'):
            try:return agent_reply('calculator',safe_math(expression))
            except (ValueError,ZeroDivisionError,SyntaxError,OverflowError):
                return agent_reply('calculator','Use a basic arithmetic expression, for example: calculate 12 * 4.')
    if any(x in low for x in ('what time','current time','today date',"today's date",'what date','time now')):
        return agent_reply('clock',datetime.now(TZ).strftime('%A, %d %B %Y, %I:%M %p')+' ('+TIMEZONE+')')
    if low in ('help','what can you do','what can you do?'):
        return agent_reply('help','I can do calculations, tell the time, and talk using a local AI model. Boss can manage private notes, reminders, tasks, and guest names from the Vault.')
    if 'remind me' in low or 'make a note' in low or 'add a task' in low:
        return agent_reply('tasks','For secure and reliable scheduling, open the Vault to create your reminder, note, or task. I will not claim to save anything from chat.')
    if any(k in low for k in ('weather','temperature outside','forecast')):
        return agent_reply('weather','Weather is not configured. I need a location and data provider to give a real forecast.')
    system=('You are Potter, a helpful concise assistant. Never assert access to personal data, private files, messages, photos, contacts, or external accounts. '
            'You cannot directly operate device controls or save reminders. Do not pretend to execute tools. '
            'Never repeat, infer, or invent private data. No private data or tools are included in this request. '
            + ('The user has an authenticated Boss session, but private actions require dedicated endpoints.' if boss else 'This is a guest session. No private information or permissions.'))
    try:
        async with httpx.AsyncClient(timeout=45) as client:
            result=await client.post(OLLAMA_CHAT_URL,json={'model':_active_model,'stream':False,'messages':[{'role':'system','content':system},{'role':'user','content':msg}]})
            result.raise_for_status()
            answer=result.json()['message']['content']
            if not isinstance(answer,str): raise ValueError('Invalid model response')
            return agent_reply('conversation',answer.strip()[:12000])
    except (httpx.HTTPError,KeyError,ValueError,TypeError):
        return agent_reply('conversation','The local AI model is offline. Start Ollama with your selected model. Calculator, clock and the Boss Vault still work.')
