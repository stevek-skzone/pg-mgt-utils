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
def pg_client(docker_compose):
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

def test_check_user_exists(pg_client):
    # Test checking if an existing user exists
    pg_client.create_user('testuser_exists', 'testpass')
    assert pg_client.check_user_exists('testuser_exists') == True

    # Test checking if a non-existing user exists
    assert pg_client.check_user_exists('nonexistinguser') == False


def test_return_user_info(pg_client):
    # Test returning information for an existing user
    pg_client.create_user('testuser_info', 'testpass')
    result = pg_client.return_user_info('testuser_info')
    assert len(result) == 1
    assert result[0]['rolname'] == 'testuser_info'

    # Test returning information for a non-existing user
    result = pg_client.return_user_info('nonexistinguser')
    assert len(result) == 0


def test_add_users_to_role(pg_client):
    # Test adding multiple users to an existing role
    pg_client.create_user('testuserar1', 'testpass')
    pg_client.create_user('testuserar2', 'testpass')
    pg_client.create_role('testrolear')
    pg_client.add_users_to_role('testrolear', ['testuserar1', 'testuserar2'])
    result = pg_client.execute_query("SELECT * FROM pg_auth_members WHERE roleid = (SELECT oid FROM pg_roles WHERE rolname = 'testrolear')")
    assert len(result) == 2

    # Test adding multiple users to a non-existing role
    with pytest.raises(Exception) as e:
        pg_client.add_users_to_role('nonexistingrole', ['testuserar1', 'testuserar2'])
    assert 'role "nonexistingrole" does not exist' in str(e.value)

    # Test adding a non-existing user to an existing role
    with pytest.raises(Exception) as e:
        pg_client.add_users_to_role('testrolear', ['testuserar1', 'nonexistinguser'])
    assert 'role "nonexistinguser" does not exist' in str(e.value)




def test_remove_users_from_role(pg_client):
    # Test removing multiple users from an existing role
    pg_client.create_user('testuserrr1', 'testpass')
    pg_client.create_user('testuserrr2', 'testpass')
    pg_client.create_role('testrolerr')
    pg_client.add_users_to_role('testrolerr', ['testuserrr1', 'testuserrr2'])
    pg_client.remove_users_from_role('testrolerr', ['testuserrr1', 'testuserrr2'])
    result = pg_client.execute_query("SELECT * FROM pg_auth_members WHERE roleid = (SELECT oid FROM pg_roles WHERE rolname = 'testrolerr')")
    assert len(result) == 0

    # Test removing multiple users from a non-existing role
    with pytest.raises(Exception) as e:
        pg_client.remove_users_from_role('nonexistingrole', ['testuserrr1', 'testuserrr2'])
    assert 'role "nonexistingrole" does not exist' in str(e.value)

    # Test removing a non-existing user from an existing role
    with pytest.raises(Exception) as e:
        pg_client.remove_users_from_role('testrolerr', ['testuserrr1', 'nonexistinguser'])
    assert 'role "nonexistinguser" does not exist' in str(e.value)


def test_grant_database_permissions_to_role(pg_client):
    # Test granting permissions to an existing role on an existing database
    pg_client.create_user('testrole', 'testpass')
    pg_client.grant_database_permissions_to_role('testrole', 'postgres', 'ALL')
    result = pg_client.execute_query("SELECT * FROM pg_database WHERE datname = 'postgres'")
    assert len(result) == 1
    assert 'testrole=CTc/postgres' in result[0]['datacl']

    # Test granting permissions to a non-existing role
    with pytest.raises(Exception) as e:
        pg_client.grant_database_permissions_to_role('nonexistingrole', 'postgres', 'CREATE,TEMPORARY,CONNECT')
    assert 'role "nonexistingrole" does not exist' in str(e.value)

    # Test granting permissions to a non-existing database
    with pytest.raises(Exception) as e:
        pg_client.grant_database_permissions_to_role('testrole', 'nonexistingdb', 'CREATE,TEMPORARY,CONNECT')
    assert 'database "nonexistingdb" does not exist' in str(e.value)

    # Test granting permissions with invalid options
    with pytest.raises(Exception) as e:
        pg_client.grant_database_permissions_to_role('testrole', 'testdb', 'INVALID_PERMISSION')
    assert 'Invalid options specified' in str(e.value)


def test_revoke_database_permissions_from_role(pg_client):
    # Test revoking permissions from an existing role on an existing database
    pg_client.create_user('testuser', 'testpass')
    pg_client.create_database('testdb')
    pg_client.grant_database_permissions_to_role('testuser', 'testdb', 'ALL')
    pg_client.revoke_database_permissions_from_role('testuser', 'testdb', 'ALL')
    result = pg_client.execute_query("SELECT datname, datacl FROM pg_database WHERE datname = 'testdb'")
    assert 'testuser' not in result[0]['datacl']

    # Test revoking permissions from a non-existing role on an existing database
    with pytest.raises(Exception):
        pg_client.revoke_database_permissions_from_role('nonexistinguser', 'testdb', 'ALL')

    # Test revoking permissions from an existing role on a non-existing database
    with pytest.raises(Exception):
        pg_client.revoke_database_permissions_from_role('testuser', 'nonexistingdb', 'ALL')


# def test_grant_default_permissions_to_role(pg_client):
#     # Test granting default permissions to an existing role on an existing schema
#     pg_client.create_role('testrole1')
#     #pg_client.create_schema('testschema')
#     pg_client.grant_default_permissions_to_role('testrole1', 'public', 'SELECT')
#     result = pg_client.execute_query("SELECT * FROM information_schema.schema_privileges")
#     assert len(result) == 1
#     assert result[0]['privilege_type'] == 'SELECT'

#     # Test granting default permissions to a non-existing role on an existing schema
#     with pytest.raises(Exception):
#         pg_client.grant_default_permissions_to_role('nonexistinguser', 'public', 'SELECT')

#     # Test granting default permissions to an existing role on a non-existing schema
#     with pytest.raises(Exception):
#         pg_client.grant_default_permissions_to_role('testrole1', 'nonexistingschema', 'SELECT')


# def test_revoke_default_permissions_from_role(pg_client):
#     # Test revoking default permissions from an existing role on an existing schema
#     pg_client.create_role('testrole2')
#     #pg_client.create_schema('testschema')
#     pg_client.grant_default_permissions_to_role('testrole2', 'public', 'SELECT')
#     pg_client.revoke_default_permissions_from_role('testrole2', 'public', 'SELECT')
#     result = pg_client.execute_query("SELECT * FROM information_schema.schema_privileges")
#     assert len(result) == 0

#     # Test revoking default permissions from a non-existing role on an existing schema
#     with pytest.raises(Exception):
#         pg_client.revoke_default_permissions_from_role('nonexistinguser', 'public', 'SELECT')

#     # Test revoking default permissions from an existing role on a non-existing schema
#     with pytest.raises(Exception):
#         pg_client.revoke_default_permissions_from_role('testrole2', 'nonexistingschema', 'SELECT')

# def test_execute_query(pg_client):
#     pg_client.execute_query('DROP TABLE IF EXISTS test_table')
#     pg_client.execute_query('CREATE TABLE test_table (id SERIAL PRIMARY KEY, name VARCHAR(50))')
#     pg_client.execute_query("INSERT INTO test_table (name) VALUES ('test')")
#     result = pg_client.execute_query('SELECT * FROM test_table')
#     assert len(result) == 1
#     assert result[0]['name'] == 'test'



# def test_create_user_error_handling(pg_client):
#     # with pytest.raises(Exception) as e:
#     #     pg_client.create_user('test;user\\\\&;', 'testpass')
#     # assert 'syntax error' in str(e.value)

#     with pytest.raises(Exception) as e:
#         pg_client.create_user('testuser', 'testpass', options='INVALID_OPTION')
#     assert 'Invalid role_attr_flags' in str(e.value)

#     with pytest.raises(Exception) as e:
#         pg_client.create_user('testuser', 'testpass')
#         pg_client.create_user('testuser', 'testpass')
#     assert 'already exists' in str(e.value)

# def test_close_connection(pg_client):
#     pg_client.close_connection()
#     assert pg_client.conn.closed == 1
