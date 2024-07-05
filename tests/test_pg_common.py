import pytest
import psycopg

from pg_mgt_utils.pg_common import pg_scram_sha256



def test_pg_scram_sha256_with_password():
    # Test generating a SCRAM-SHA-256 password hash with a provided password
    password = 'my_password12345'
    result = pg_scram_sha256(password)
    assert isinstance(result, str)
    assert result.startswith('SCRAM-SHA-256')


def test_pg_scram_sha256_without_password():
    # Test generating a SCRAM-SHA-256 password hash without a provided password
    result = pg_scram_sha256()
    assert isinstance(result, str)
    assert result.startswith('SCRAM-SHA-256')


def test_pg_scram_sha256_with_invalid_password():
    # Test generating a SCRAM-SHA-256 password hash with an invalid password
    password = 'short'
    with pytest.raises(ValueError):
        pg_scram_sha256(password)

# Example function to demonstrate psycopg3 usage
def test_pg_scram_sha256_connection():
    # Connect to your database
    username = 'test_user'
    password = 'test_password'
    with psycopg.connect("dbname=postgres user=postgres password=Password123 host=0.0.0.0") as conn:
        with conn.cursor() as cur:
            conn.autocommit = True
            # Use SCRAM-SHA-256 encrypted password to create a user
            encrypted_password = pg_scram_sha256(password)
            cur.execute(f"DROP ROLE IF EXISTS {username}")
            cur.execute(f"CREATE ROLE {username} WITH LOGIN PASSWORD '{encrypted_password}'")

        # Attempt to connect to the database using the new user
        try:
            test_conn = psycopg.connect(dbname="postgres", user=username, password=password, host="0.0.0.0")
            # If connection is successful, the password works
            assert test_conn is not None
            test_conn.close()
        finally:
            # Cleanup: remove the test user
            cur = conn.cursor()
            cur.execute(f"DROP ROLE IF EXISTS {username};")
            cur.close()
            conn.close()