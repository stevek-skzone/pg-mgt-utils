import pytest

from pg_mgt_utils.pg_client import PgClient


@pytest.fixture(scope='session')
def pg_client(docker_compose):
    pg_client = PgClient('localhost', 'postgres', 'Password123', 'postgres')
    yield pg_client
    pg_client.close_connection()


def test_create_database(pg_client):
    pg_client.create_database('new_db')
    assert pg_client.check_database_exists('new_db') == True

    pg_client.create_database('new_db2', encoding='UTF8', connection_limit=10)
    assert pg_client.check_database_exists('new_db2') == True

    # Test creating a new database with a specified owner
    pg_client.create_database('test_db2', 'postgres')
    assert pg_client.check_database_exists('test_db2') == True

    # Test creating a new database with an invalid encoding
    with pytest.raises(Exception):
        pg_client.create_database('test_db3', encoding='INVALID_ENCODING')


def test_drop_database(pg_client):
    # Test dropping an existing database
    pg_client.create_database('test_db')
    pg_client.drop_database('test_db')
    assert pg_client.check_database_exists('test_db') == False

    # # Test dropping a non-existent database
    # with pytest.raises(Exception):
    # pg_client.drop_database('non_existent_db')


def test_alter_database(pg_client):
    pg_client.create_database('new_db_alter')
    pg_client.alter_database('new_db_alter', connection_limit=10)
    info = pg_client.return_database_info('new_db_alter')
    assert info[0]['datname'] == 'new_db_alter'
    assert info[0]['datconnlimit'] == 10


def test_check_database_exists(pg_client):
    # Test checking for an existing database
    pg_client.create_database('test_db')
    assert pg_client.check_database_exists('test_db') == True

    # Test checking for a non-existent database
    assert pg_client.check_database_exists('non_existent_db') == False


def test_return_database_info(pg_client):
    # Test returning info for an existing database
    pg_client.create_database('new_db_info')
    info = pg_client.return_database_info('new_db_info')
    assert info[0]['datname'] == 'new_db_info'


def test_execute_query(pg_client):
    # Test executing a simple query
    result = pg_client.execute_query('SELECT 1 as col1')
    assert result[0] == {'col1': 1}

    # Test executing a query that returns no rows
    result = pg_client.execute_query('SELECT * FROM nonexistent_table')
    assert result == []


# def test_get_database_owner(pg_client):
#     # Test getting the owner of an existing database
#     pg_client.create_database('test_db', 'postgres')
#     assert pg_client.get_database_owner('test_db') == 'postgres'

#     # Test getting the owner of a non-existent database
#     with pytest.raises(Exception):
#         pg_client.get_database_owner('non_existent_db')


# def test_validate_encoding(pg_client):
#     # Test validating a valid encoding
#     pg_client.validate_encoding('UTF8')

#     # Test validating an invalid encoding
#     with pytest.raises(Exception):
#         pg_client.validate_encoding('INVALID_ENCODING')


# def test_get_database_encoding(pg_client):
#     # Test getting the encoding of an existing database
#     pg_client.create_database('test_db', encoding='UTF8')
#     assert pg_client.get_database_encoding('test_db') == 'UTF8'

#     # Test getting the encoding of a non-existent database
#     with pytest.raises(Exception):
#         pg_client.get_database_encoding('non_existent_db')


# def test_get_database_collation(pg_client):
#     # Test getting the collation of an existing database
#     pg_client.create_database('test_db', collation='en_US.utf8')
#     assert pg_client.get_database_collation('test_db') == 'en_US.utf8'

#     # Test getting the collation of a non-existent database
#     with pytest.raises(Exception):
#         pg_client.get_database_collation('non_existent_db')


# def test_get_database_ctype(pg_client):
#     # Test getting the ctype of an existing database
#     pg_client.create_database('test_db', ctype='en_US.utf8')
#     assert pg_client.get_database_ctype('test_db') == 'en_US.utf8'

#     # Test getting the ctype of a non-existent database
#     with pytest.raises(Exception):
#         pg_client.get_database_ctype('non_existent_db')
