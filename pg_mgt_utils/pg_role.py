from typing import Any, Optional, List, Tuple

import itertools
import logging
from psycopg2.extensions import AsIs

logger = logging.getLogger(__name__)

FLAGS = ('SUPERUSER', 'CREATEROLE', 'CREATEDB', 'INHERIT', 'LOGIN', 'REPLICATION', 'BYPASSRLS')

class InvalidFlagsError(Exception):
    pass

def _parse_role_attrs(role_attr_flags: str) -> str:
    flags = frozenset(role.upper() for role in role_attr_flags.split(','))

    valid_flags = frozenset(itertools.chain(FLAGS, (f"NO{flag}" for flag in FLAGS)))

    if not flags.issubset(valid_flags):
        raise InvalidFlagsError('Invalid role_attr_flags specified: %s' %
                                ' '.join(flags.difference(valid_flags)))

    return ' '.join(flags)


class PgRole:
    """
    A class for managing PostgreSQL roles and users.
    """
    def __init__(self, conn: Any):
        """
        Initializes a new instance of the PgRole class.

        :param conn: A psycopg2 connection object.
        """
        self.conn = conn

    def execute_query(self, query: str) -> List[Tuple]:
        """
        Executes the specified SQL query and returns the results.

        :param query: The SQL query to execute.
        :return: A list of tuples containing the query results.
        """
        with self.conn.cursor() as cur:
            cur.execute(query)
            return cur.fetchall()

    def create_user(self, username: str, password: str, options: Optional[str] = None, max_connections: Optional[int] = None, expiry: Optional[str] = None) -> None:
        """
        Creates a new PostgreSQL user with the specified username and password.

        :param username: The username of the new user.
        :param password: The password of the new user.
        :param options: Additional options to include in the CREATE USER statement.
        :param max_connections: The maximum number of connections allowed for the new user.
        :param expiry: The expiry date for the new user.
        """
        query = 'CREATE USER "%s" WITH PASSWORD %s'
        if max_connections:
            query += f' CONNECTION LIMIT {max_connections}'
        if expiry:
            query += f' VALID UNTIL \'{expiry}\''
        if options:
            options = _parse_role_attrs(options)
            query += ' ' + ' '.join([options])
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, (AsIs(username), password))
            logger.info(f"Created user {username}")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"Failed to create user {username}")
            raise e

    def drop_user(self, username: str) -> None:
        """
        Drops an existing PostgreSQL user with the specified username.

        :param username: The username of the user to drop.
        """
        query = 'DROP USER IF EXISTS "%s"'
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, (AsIs(username),))
            logger.info(f"Dropped user {username}")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"Failed to drop user {username}")
            raise e

    def alter_user(self, username: str, password: Optional[str] = None, options: Optional[str] = None, max_connections: Optional[int] = None, expiry: Optional[str] = None) -> None:
        """
        Alters an existing PostgreSQL user with the specified username.

        :param username: The username of the user to alter.
        :param password: The new password for the user.
        :param options: Additional options to include in the ALTER USER statement.
        :param max_connections: The new maximum number of connections allowed for the user.
        :param expiry: The new expiry date for the user.
        """
        query = 'ALTER USER "%s"'
        if password:
            query += ' WITH PASSWORD %s'
        if max_connections:
            query += f' CONNECTION LIMIT {max_connections}'
        if expiry:
            query += f' VALID UNTIL \'{expiry}\''
        if options:
            options = _parse_role_attrs(options)
            query += ' ' + ' '.join([options])
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, (AsIs(username), password))
            logger.info(f"Altered user {username}")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"Failed to alter user {username}")
            raise e
        
    def add_role(self, rolename: str) -> None:
        """
        Creates a new PostgreSQL role with the specified rolename.

        :param rolename: The name of the new role.
        """
        query = f"CREATE ROLE {rolename}"
        try:
            self.execute_query(query)
            logging.info(f"Created role {rolename}")
        except Exception as e:
            logging.error(f"Failed to create role {rolename}: {e}")
            raise e

    def drop_role(self, rolename: str) -> None:
        """
        Drops an existing PostgreSQL role with the specified rolename.

        :param rolename: The name of the role to drop.
        """
        query = f"DROP ROLE {rolename}"
        try:
            self.execute_query(query)
            logging.info(f"Dropped role {rolename}")
        except Exception as e:
            logging.error(f"Failed to drop role {rolename}: {e}")
            raise e

    def add_users_to_role(self, rolename: str, *usernames: str) -> None:
        """
        Adds one or more PostgreSQL users with the specified usernames to an existing PostgreSQL role with the specified rolename.

        :param rolename: The name of the role to add users to.
        :param usernames: The usernames of the users to add to the role.
        """
        query = f"GRANT {rolename} TO {', '.join(usernames)}"
        try:
            self.execute_query(query)
            logging.info(f"Added users {', '.join(usernames)} to role {rolename}")
        except Exception as e:
            logging.error(f"Failed to add users {', '.join(usernames)} to role {rolename}: {e}")
            raise e

    def remove_users_from_role(self, rolename: str, *usernames: str) -> None:
        """
        Removes one or more PostgreSQL users with the specified usernames from an existing PostgreSQL role with the specified rolename.

        :param rolename: The name of the role to remove users from.
        :param usernames: The usernames of the users to remove from the role.
        """
        query = f"REVOKE {rolename} FROM {', '.join(usernames)}"
        try:
            self.execute_query(query)
            logging.info(f"Removed users {', '.join(usernames)} from role {rolename}")
        except Exception as e:
            logging.error(f"Failed to remove users {', '.join(usernames)} from role {rolename}: {e}")
            raise e

    def grant_database_permissions_to_role(self, rolename: str, database: str, permissions: str) -> None:
        """
        Grants the specified permissions on the specified database to an existing PostgreSQL role with the specified rolename.

        :param rolename: The name of the role to grant permissions to.
        :param database: The name of the database to grant permissions on.
        :param permissions: The permissions to grant.
        """
        query = f"GRANT {permissions} ON DATABASE {database} TO {rolename}"
        try:
            self.execute_query(query)
            logging.info(f"Granted {permissions} permissions on database {database} to role {rolename}")
        except Exception as e:
            logging.error(f"Failed to grant {permissions} permissions on database {database} to role {rolename}: {e}")
            raise e

    def revoke_database_permissions_from_role(self, rolename: str, database: str, permissions: str) -> None:
        """
        Revokes the specified permissions on the specified database from an existing PostgreSQL role with the specified rolename.

        :param rolename: The name of the role to revoke permissions from.
        :param database: The name of the database to revoke permissions on.
        :param permissions: The permissions to revoke.
        """
        query = f"REVOKE {permissions} ON DATABASE {database} FROM {rolename}"
        try:
            self.execute_query(query)
            logging.info(f"Revoked {permissions} permissions on database {database} from role {rolename}")
        except Exception as e:
            logging.error(f"Failed to revoke {permissions} permissions on database {database} from role {rolename}: {e}")
            raise e

    def grant_default_permissions_to_role(self, rolename: str, schema: str, permissions: str) -> None:
        """
        Grants the specified permissions on the specified schema to an existing PostgreSQL role with the specified rolename.

        :param rolename: The name of the role to grant permissions to.
        :param schema: The name of the schema to grant permissions on.
        :param permissions: The permissions to grant.
        """
        query = f"GRANT {permissions} ON SCHEMA {schema} TO {rolename}"
        try:
            self.execute_query(query)
            logging.info(f"Granted {permissions} permissions on schema {schema} to role {rolename}")
        except Exception as e:
            logging.error(f"Failed to grant {permissions} permissions on schema {schema} to role {rolename}: {e}")
            raise e

    def revoke_default_permissions_from_role(self, rolename: str, schema: str, permissions: str) -> None:
        """
        Revokes the specified permissions on the specified schema from an existing PostgreSQL role with the specified rolename.

        :param rolename: The name of the role to revoke permissions from.
        :param schema: The name of the schema to revoke permissions on.
        :param permissions: The permissions to revoke.
        """
        query = f"REVOKE {permissions} ON SCHEMA {schema} FROM {rolename}"
        try:
            self.execute_query(query)
            logging.info(f"Revoked {permissions} permissions on schema {schema} from role {rolename}")
        except Exception as e:
            logging.error(f"Failed to revoke {permissions} permissions on schema {schema} from role {rolename}: {e}")
            raise e

    def check_user_exists(self, username: str) -> bool:
        """
        Checks if a PostgreSQL user with the specified username exists.

        :param username: The username of the user to check.
        :return: True if the user exists, False otherwise.
        """
        query = f"SELECT 1 FROM pg_roles WHERE rolname='{username}'"
        try:
            result = self.execute_query(query)
            return bool(result)
        except Exception as e:
            logging.error(f"Failed to check if user {username} exists: {e}")
            raise e

    def return_user_info(self, username: str) -> List[Tuple]:
        """
        Returns information about a PostgreSQL user with the specified username.

        :param username: The username of the user to return information for.
        :return: A list of tuples containing the user's attributes.
        """
        query = f"SELECT * FROM pg_roles WHERE rolname='{username}'"
        try:
            result = self.execute_query(query)
            return result
        except Exception as e:
            logging.error(f"Failed to return info for user {username}: {e}")
            raise e