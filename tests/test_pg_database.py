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

    with pytest.raises(Exception):
        pg_client.create_database('new_db2', encoding='bad_encoding', connection_limit=10)


def test_drop_database(pg_client):
    pg_client.create_database('new_db_drop')
    pg_client.drop_database('new_db_drop')


def test_alter_database(pg_client):
    pg_client.create_database('new_db_alter')
    pg_client.alter_database('new_db_alter', connection_limit=10)
    info = pg_client.return_database_info('new_db_alter')
    assert info[0]['datname'] == 'new_db_alter'
    assert info[0]['datconnlimit'] == 10


def test_check_database_exists(pg_client):
    # Test checking an existing database
    pg_client.create_database('new_db_check')
    assert pg_client.check_database_exists('new_db_check') == True

    # Test checking a non-existent database
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
