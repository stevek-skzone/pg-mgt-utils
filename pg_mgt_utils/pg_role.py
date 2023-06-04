from typing import Any, Optional, List, Tuple

import itertools
import logging
from psycopg import sql
from pg_mgt_utils.pg_common import logger, pg_quote_identifier
from datetime import datetime, timedelta


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

    def create_user(self, username: str, password: str, options: Optional[str] = None, max_connections: Optional[int] = None, expiry: Optional[datetime] = None) -> None:
        """
        Creates a new PostgreSQL user with the specified username and password.

        :param username: The username of the new user.
        :param password: The password of the new user.
        :param options: Additional options to include in the CREATE USER statement.
        :param max_connections: The maximum number of connections allowed for the new user.
        :param expiry: The expiry date for the new user.
        """
        query = "CREATE USER {} WITH PASSWORD {}"
        if max_connections:
            query += f' CONNECTION LIMIT {max_connections}'
        if expiry:
            query += f' VALID UNTIL \'{expiry}\''
        if options:
            options = _parse_role_attrs(options)
            query += ' ' + ' '.join([options])
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(username), password))
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
        query = "DROP USER IF EXISTS {}"
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(username)))
            logger.info(f"Dropped user {username}")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"Failed to drop user {username}")
            raise e

    def alter_user(self, username: str, password: Optional[str] = None, options: Optional[str] = None, max_connections: Optional[int] = None, expiry: Optional[datetime] = None) -> None:
        """
        Alters an existing PostgreSQL user with the specified username.

        :param username: The username of the user to alter.
        :param password: The new password for the user.
        :param options: Additional options to include in the ALTER USER statement.
        :param max_connections: The new maximum number of connections allowed for the user.
        :param expiry: The new expiry date for the user.
        """
        query = "ALTER USER {}"
        if password:
            query += ' WITH PASSWORD {}'
        if max_connections:
            query += f' CONNECTION LIMIT {max_connections}'
        if expiry:
            query += f' VALID UNTIL \'{expiry}\''
        if options:
            options = _parse_role_attrs(options)
            query += ' ' + ' '.join([options])
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(username), password))
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
        query = "CREATE ROLE {}"
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(rolename)))
            logging.info(f"Created role {rolename}")
        except Exception as e:
            logging.error(f"Failed to create role {rolename}: {e}")
            raise e

    # def drop_role(self, rolename: str) -> None:
    #     """
    #     Drops an existing PostgreSQL role with the specified rolename.

    #     :param rolename: The name of the role to drop.
    #     """
    #     query = "DROP ROLE %s"
    #     try:
    #         with self.conn.cursor() as cur:
    #             cur.execute(query, (AsIs(pg_quote_identifier(rolename, 'role')),))
    #         logging.info(f"Dropped role {rolename}")
    #     except Exception as e:
    #         logging.error(f"Failed to drop role {rolename}: {e}")
    #         raise e

    # def add_user_to_role(self, rolename: str, username: str) -> None:
    #     """
    #     Adds a PostgreSQL user with the specified username to an existing PostgreSQL role with the specified rolename.

    #     :param rolename: The name of the role to add the user to.
    #     :param username: The username of the user to add to the role.
    #     """
    #     query = "GRANT %s TO %s"
    #     try:
    #         with self.conn.cursor() as cur:
    #             cur.execute(query, (AsIs(pg_quote_identifier(rolename, 'role')), AsIs(pg_quote_identifier(username, 'role'))))
    #         logging.info(f"Added user {username} to role {rolename}")
    #     except Exception as e:
    #         logging.error(f"Failed to add user {username} to role {rolename}: {e}")
    #         raise e

    # def add_users_to_role(self, rolename: str, usernames: List[str]) -> None:
    #     """
    #     Adds one or more PostgreSQL users with the specified usernames to an existing PostgreSQL role with the specified rolename.

    #     :param rolename: The name of the role to add users to.
    #     :param usernames: The usernames of the users to add to the role.
    #     """
    #     for username in usernames:
    #         self.add_user_to_role(rolename, username)

    # def remove_user_from_role(self, rolename: str, username: str) -> None:
    #     """
    #     Removes one or more PostgreSQL users with the specified usernames from an existing PostgreSQL role with the specified rolename.

    #     :param rolename: The name of the role to remove users from.
    #     :param usernames: The usernames of the users to remove from the role.
    #     """
    #     query = "REVOKE %s FROM %s"
    #     try:
    #         with self.conn.cursor() as cur:
    #             cur.execute(query, (AsIs(pg_quote_identifier(rolename, 'role')), AsIs(pg_quote_identifier(username, 'role'))))
    #         logging.info(f"Removed user {username} from role {rolename}")
    #     except Exception as e:
    #         logging.error(f"Failed to remove user {username} from role {rolename}: {e}")
    #         raise e

    # def remove_users_to_role(self, rolename: str, usernames: List[str]) -> None:
    #     """
    #     Removes one or more PostgreSQL users with the specified usernames from an existing PostgreSQL role with the specified rolename.

    #     :param rolename: The name of the role to remove users to.
    #     :param usernames: The usernames of the users to remove from the role.
    #     """
    #     for username in usernames:
    #         self.remove_user_from_role(rolename, username)

    # def grant_database_permissions_to_role(self, rolename: str, database: str, permissions: str) -> None:
    #     """
    #     Grants the specified permissions on the specified database to an existing PostgreSQL role with the specified rolename.

    #     :param rolename: The name of the role to grant permissions to.
    #     :param database: The name of the database to grant permissions on.
    #     :param permissions: The permissions to grant.
    #     """
    #     query = "GRANT %s ON DATABASE %s TO %s"
    #     try:
    #         with self.conn.cursor() as cur:
    #             cur.execute(query, (permissions, pg_quote_identifier(database, 'database'), pg_quote_identifier(rolename, 'role')))
    #         logging.info(f"Granted {permissions} permissions on database {database} to role {rolename}")
    #     except Exception as e:
    #         logging.error(f"Failed to grant {permissions} permissions on database {database} to role {rolename}: {e}")
    #         raise e

    # def revoke_database_permissions_from_role(self, rolename: str, database: str, permissions: str) -> None:
    #     """
    #     Revokes the specified permissions on the specified database from an existing PostgreSQL role with the specified rolename.

    #     :param rolename: The name of the role to revoke permissions from.
    #     :param database: The name of the database to revoke permissions on.
    #     :param permissions: The permissions to revoke.
    #     """
    #     query = "REVOKE %s ON DATABASE %s FROM %s"
    #     try:
    #         with self.conn.cursor() as cur:
    #             cur.execute(query, (permissions, pg_quote_identifier(database, 'database'), pg_quote_identifier(rolename, 'role')))
    #         logging.info(f"Revoked {permissions} permissions on database {database} from role {rolename}")
    #     except Exception as e:
    #         logging.error(f"Failed to revoke {permissions} permissions on database {database} from role {rolename}: {e}")
    #         raise e

    # def grant_default_permissions_to_role(self, rolename: str, schema: str, permissions: str) -> None:
    #     """
    #     Grants the specified permissions on the specified schema to an existing PostgreSQL role with the specified rolename.

    #     :param rolename: The name of the role to grant permissions to.
    #     :param schema: The name of the schema to grant permissions on.
    #     :param permissions: The permissions to grant.
    #     """
    #     query = "GRANT %s ON SCHEMA %s TO %s"
    #     try:
    #         with self.conn.cursor() as cur:
    #             cur.execute(query, (permissions, pg_quote_identifier(schema, 'schema'), pg_quote_identifier(rolename, 'role')))
    #         logging.info(f"Granted {permissions} permissions on schema {schema} to role {rolename}")
    #     except Exception as e:
    #         logging.error(f"Failed to grant {permissions} permissions on schema {schema} to role {rolename}: {e}")
    #         raise e

    # def revoke_default_permissions_from_role(self, rolename: str, schema: str, permissions: str) -> None:
    #     """
    #     Revokes the specified permissions on the specified schema from an existing PostgreSQL role with the specified rolename.

    #     :param rolename: The name of the role to revoke permissions from.
    #     :param schema: The name of the schema to revoke permissions on.
    #     :param permissions: The permissions to revoke.
    #     """
    #     query = "REVOKE %s ON SCHEMA %s FROM %s"
    #     try:
    #         with self.conn.cursor() as cur:
    #             cur.execute(query, (permissions, pg_quote_identifier(schema, 'schema'), pg_quote_identifier(rolename, 'role')))
    #         logging.info(f"Revoked {permissions} permissions on schema {schema} from role {rolename}")
    #     except Exception as e:
    #         logging.error(f"Failed to revoke {permissions} permissions on schema {schema} from role {rolename}: {e}")
    #         raise e

    # def check_user_exists(self, username: str) -> bool:
    #     """
    #     Checks if a PostgreSQL user with the specified username exists.

    #     :param username: The username of the user to check.
    #     :return: True if the user exists, False otherwise.
    #     """
    #     query = "SELECT 1 FROM pg_roles WHERE rolname=%s"
    #     try:
    #         with self.conn.cursor() as cur:
    #             cur.execute(query, (pg_quote_identifier(username, 'user'),))
    #             result = cur.fetchone()
    #             return bool(result)
    #     except Exception as e:
    #         logging.error(f"Failed to check if user {username} exists: {e}")
    #         raise e

    # def return_user_info(self, username: str) -> List[Tuple]:
    #     """
    #     Returns information about a PostgreSQL user with the specified username.

    #     :param username: The username of the user to return information for.
    #     :return: A list of tuples containing the user's attributes.
    #     """
    #     query = "SELECT * FROM pg_roles WHERE rolname=%s"
    #     try:
    #         with self.conn.cursor() as cur:
    #             cur.execute(query, (pg_quote_identifier(username, 'user'),))
    #             result = cur.fetchall()
    #             return result
    #     except Exception as e:
    #         logging.error(f"Failed to return info for user {username}: {e}")
    #         raise e
