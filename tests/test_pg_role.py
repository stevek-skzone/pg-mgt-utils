import pytest
from pg_mgt_utils.pg_client import PgClient
from base64 import standard_b64encode
from hashlib import pbkdf2_hmac, sha256
from os import urandom
import hmac


def b64enc(b: bytes) -> str:
    return standard_b64encode(b).decode('utf8')


def pg_scram_sha256(passwd: str) -> str:
    salt_size = 16
    digest_len = 32
    iterations = 4096
    salt = urandom(salt_size)
    digest_key = pbkdf2_hmac('sha256', passwd.encode('utf8'), salt, iterations,
                             digest_len)
    client_key = hmac.digest(digest_key, 'Client Key'.encode('utf8'), 'sha256')
    stored_key = sha256(client_key).digest()
    server_key = hmac.digest(digest_key, 'Server Key'.encode('utf8'), 'sha256')
    return (
        f'SCRAM-SHA-256${iterations}:{b64enc(salt)}'
        f'${b64enc(stored_key)}:{b64enc(server_key)}'
    )


@pytest.fixture(scope='session')
def pg_client(docker_containers):
    client = PgClient('localhost', 'postgres', 'Password123', 'postgres')
    yield client
    client.close_connection()


def test_create_user(pg_client):
    pg_client.drop_user('testusercreate')
    pg_client.create_user('testusercreate', 'testpass')
    result = pg_client.execute_query("SELECT * FROM pg_roles WHERE rolname = 'testusercreate'")
    
    assert len(result) == 1


def test_drop_user(pg_client):
    pg_client.create_user('testuserdrop', 'testpass')
    pg_client.drop_user('testuserdrop')
    result = pg_client.execute_query("SELECT * FROM pg_roles WHERE rolname = 'testuserdrop'")
    assert len(result) == 0


def test_alter_user(pg_client):
    pg_client.drop_user('testuseralter')
    pg_client.create_user('testuseralter', 'testpass')

    new_pass = pg_scram_sha256('newpass')
    pg_client.alter_user('testuseralter', password=new_pass, options='NOSUPERUSER', max_connections=10, expiry='2022-01-01')
    result = pg_client.execute_query("SELECT * FROM pg_authid WHERE rolname = 'testuseralter'")
    print(result)
    assert len(result) == 1
    assert result[0]['rolpassword'] == new_pass
    assert result[0]['rolconnlimit'] == 10
    assert str(result[0]['rolvaliduntil']) == '2022-01-01 00:00:00+00:00'


def test_execute_query(pg_client):
    pg_client.execute_query('DROP TABLE IF EXISTS test_table')
    pg_client.execute_query('CREATE TABLE test_table (id SERIAL PRIMARY KEY, name VARCHAR(50))')
    pg_client.execute_query("INSERT INTO test_table (name) VALUES ('test')")
    result = pg_client.execute_query('SELECT * FROM test_table')
    assert len(result) == 1
    assert result[0]['name'] == 'test'



def test_create_user_error_handling(pg_client):
    with pytest.raises(Exception) as e:
        pg_client.create_user('test"user\\\\&;', 'testpass')
    assert 'syntax error' in str(e.value)

    with pytest.raises(Exception) as e:
        pg_client.create_user('testuser', 'testpass', options='INVALID_OPTION')
    assert 'Invalid role_attr_flags' in str(e.value)

    with pytest.raises(Exception) as e:
        pg_client.create_user('testuser', 'testpass')
        pg_client.create_user('testuser', 'testpass')
    assert 'already exists' in str(e.value)

def test_close_connection(pg_client):
    pg_client.close_connection()
    assert pg_client.conn.closed == 1
