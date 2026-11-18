import importlib
from datetime import datetime, timedelta, timezone
from fastapi.testclient import TestClient
import pytest

@pytest.fixture
def client(monkeypatch,tmp_path):
    monkeypatch.setenv('POTTER_DATA_DIR',str(tmp_path))
    import app
    module=importlib.reload(app)
    module.setup_db()
    with TestClient(module.app) as test:
        yield test

def setup(client):
    response=client.post('/api/setup',json={'pin':'a-strong-test-pin'})
    assert response.status_code==200,response.text


def test_health_and_start(client):
    assert client.get('/api/health').json()['status']=='ok'
    assert client.get('/').status_code==200
    assert client.get('/api/status').json()['role']=='guest'


def test_boss_setup_login_logout(client):
    setup(client)
    assert client.get('/api/status').json()['role']=='boss'
    assert client.post('/api/setup',json={'pin':'another-strong-pin'}).status_code==409
    assert client.post('/api/logout').status_code==200
    assert client.get('/api/status').json()['role']=='guest'
    assert client.post('/api/login',json={'pin':'incorrect-password'}).status_code==401
    assert client.post('/api/login',json={'pin':'a-strong-test-pin'}).status_code==200
    assert client.get('/api/status').json()['role']=='boss'


def test_guest_cannot_read_or_write_private(client):
    for path in ('notes','reminders','tasks','guests'):
        assert client.get('/api/'+path).status_code==403
    assert client.post('/api/notes',json={'text':'secret'}).status_code==403
    assert client.post('/api/tasks',json={'text':'secret'}).status_code==403
    assert client.post('/api/guests',json={'name':'Sam','consent':True}).status_code==403
    assert client.get('/api/reminders/due').status_code==403
    assert client.delete('/api/notes/1').status_code==403
    assert client.patch('/api/tasks/1',json={'done':True}).status_code==403


def test_notes_and_guest_consent(client):
    setup(client)
    assert client.post('/api/notes',json={'text':'private text'}).status_code==200
    note=client.get('/api/notes').json()[0]
    assert note['body']=='private text'
    assert client.post('/api/guests',json={'name':'Sam','consent':False}).status_code==400
    assert client.post('/api/guests',json={'name':'Sam','consent':True}).status_code==200
    guest=client.get('/api/guests').json()[0]
    assert guest['name']=='Sam'
    assert client.delete('/api/guests/'+str(guest['id'])).status_code==200
    assert client.delete('/api/notes/'+str(note['id'])).status_code==200
    assert client.get('/api/notes').json()==[]


def test_reminder_due_and_task_lifecycle(client):
    setup(client)
    due=(datetime.now(timezone.utc)+timedelta(minutes=20)).isoformat()
    assert client.post('/api/reminders',json={'text':'Drink water','due':due}).status_code==200
    assert client.get('/api/reminders/due').json()==[]
    reminders=client.get('/api/reminders').json()
    assert reminders[0]['delivered']==0
    assert client.post('/api/reminders',json={'text':'past','due':'2020-01-01T12:00:00Z'}).status_code==422
    assert client.post('/api/reminders',json={'text':'invalid','due':'2028-01-01T12:00:00'}).status_code==422
    task=client.post('/api/tasks',json={'text':'Clean desk'}).json()
    assert client.patch('/api/tasks/'+str(task['id']),json={'done':True}).status_code==200
    assert client.get('/api/tasks').json()[0]['done']==1
    assert client.delete('/api/tasks/'+str(task['id'])).status_code==200


def test_agents_math_clock_and_privacy(client):
    assert len(client.get('/api/agents').json()['agents'])>=7
    assert client.post('/api/chat',json={'text':'calculate 7 * (8 + 2)'}).json()['reply']=='70'
    assert client.post('/api/chat',json={'text':'calculate 1/0'}).json()['agent']=='calculator'
    assert client.post('/api/chat',json={'text':'what time is it?'}).json()['agent']=='clock'
    out=client.post('/api/chat',json={'text':'show my messages'}).json()
    assert out['agent']=='privacy'
    assert 'authentication' in out['reply'].lower()
    assert client.post('/api/chat',json={'text':'help'}).json()['agent']=='help'


def test_origin_protection(client):
    response=client.post('/api/chat',json={'text':'help'},headers={'Origin':'https://evil.example'})
    assert response.status_code==403


def test_security_cookie(client):
    setup(client)
    cookie=client.cookies.get('potter_session')
    assert cookie and len(cookie)>30
    client.post('/api/logout')
    assert client.get('/api/notes').status_code==403
