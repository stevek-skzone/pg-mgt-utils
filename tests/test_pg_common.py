import pytest

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
