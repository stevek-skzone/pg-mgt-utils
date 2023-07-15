# pylint: disable=line-too-long
import logging
import os
import re

log_level = os.environ.get('LOG_LEVEL', 'INFO')
logging.basicConfig(level=log_level)

logger = logging.getLogger(__name__)


VALID_ROLES = frozenset(
    [
        'SUPERUSER',
        'CREATEROLE',
        'CREATEDB',
        'INHERIT',
        'LOGIN',
        'REPLICATION',
        'BYPASSRLS',
        'NOSUPERUSER',
        'NOCREATEROLE',
        'NOCREATEDB',
        'NOINHERIT',
        'NOLOGIN',
        'NOREPLICATION',
        'NOBYPASSRLS',
    ]
)

VALID_DB_PRIVS = frozenset(['CREATE', 'CONNECT', 'TEMPORARY', 'TEMP', 'ALL PRIVILEGES'])

VALID_OBJ_PRIVS = frozenset(['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE', 'REFERENCES', 'TRIGGER', 'ALL'])


class InvalidOptionsError(Exception):
    """Exception raised when invalid options are provided.

    Attributes:
        message -- explanation of the error
    """

    def __init__(self, message="Invalid options provided."):
        self.message = message
        super().__init__(self.message)


def _return_valid_options(option_type: str) -> frozenset:
    """
    Returns a frozenset of valid options for a role.

    :param option_type: A option type (e.g. database, role, object).
    :return: A frozenset of valid options.
    """
    choice = {"database": VALID_DB_PRIVS, "role": VALID_ROLES, "object": VALID_OBJ_PRIVS}
    return choice[option_type]


def parse_options(options: str, option_type: str, separator: str = ' ') -> str:
    """
    Parses a string of options and returns a string with the valid options separated by a specified separator.

    Args:
        options (str): A string of options separated by commas.
        option_type (str): The type of options to parse. Valid values are 'database', 'role', and 'object'.
        separator (str, optional): The separator to use between the valid options. Defaults to ' '.

    Returns:
        str: A string with the valid options separated by the specified separator.

    Raises:
        InvalidOptionsError: If any of the options specified are not valid for the specified type.
    """
    valid_options = _return_valid_options(option_type)
    options_set = frozenset(option.upper() for option in options.split(','))

    if not options_set.issubset(valid_options):
        raise InvalidOptionsError(f"Invalid options specified: {' '.join(options_set.difference(valid_options))}")

    return separator.join(options_set)


def validate_encoding(encoding: str) -> bool:
    """
    Validates a PostgreSQL database encoding option using a regular expression.

    Args:
        encoding (str): The database encoding option to validate.

    Returns:
        bool: True if the encoding option is valid, False otherwise.
    """
    encoding_regex = re.compile(
        r'^UTF8$|^LATIN[1-9][0-6]?$|^WIN(125[0-8]|866)$|^EUC_JP$|^EUC_CN$|^EUC_KR$|^JOHAB$|^SHIFT_JIS$|^MULE_INTERNAL$|^TCVN$|^TCVN5712$|^ISO-8859-[1-9][0-9]?$|^KOI8-R$|^WIN(1251|1252|1256)$|^WIN(866|874)$|^ISO-8859-5$|^ISO-8859-6$|^ISO-8859-7$|^ISO-8859-8$|^WIN(1250|1253|1254|1255|1257|1258)$'
    )

    if re.match(encoding_regex, encoding):
        return True

    raise InvalidOptionsError(f'Invalid encoding specified: {encoding}')
