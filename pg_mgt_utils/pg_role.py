# pylint: disable=line-too-long
from datetime import datetime
from typing import Any, List, Optional, Tuple

from psycopg import sql
from psycopg.rows import dict_row

from pg_mgt_utils.pg_common import logger, parse_options


class PgRole:
    """
    A class for managing PostgreSQL roles and users.
    """

    def __init__(self, conn: Any):
        """
        Initializes a new instance of the PgRole class.

        :param conn: A psycopg (psycopg3) connection object.
        """
        self.conn = conn

    def create_user(
        self,
        username: str,
        password: str,
        options: Optional[str] = None,
        max_connections: Optional[int] = None,
        expiry: Optional[datetime] = None,
    ) -> None:
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
            options = parse_options(options, 'role')
            query += ' ' + ' '.join([options])
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(username), password))  # type: ignore
            logger.info("Created user %s", username)
        except Exception as err:
            self.conn.rollback()
            logger.error("Failed to create user %s", username)
            raise err

    def drop_user(self, username: str) -> None:
        """
        Drops an existing PostgreSQL user with the specified username.

        :param username: The username of the user to drop.
        """
        query = "DROP USER IF EXISTS {}"
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(username)))
            logger.info("Dropped user %s", username)
        except Exception as err:
            self.conn.rollback()
            logger.error("Failed to drop user %s", username)
            raise err

    def alter_user(
        self,
        username: str,
        password: Optional[str] = None,
        options: Optional[str] = None,
        max_connections: Optional[int] = None,
        expiry: Optional[datetime] = None,
    ) -> None:
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
            options = parse_options(options, 'role')
            query += ' ' + ' '.join([options])
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(username), password))  # type: ignore
            logger.info("Altered user %s", username)
        except Exception as err:
            self.conn.rollback()
            logger.error("Failed to alter user %s", username)
            raise err

    def create_role(self, rolename: str) -> None:
        """
        Creates a new PostgreSQL role with the specified rolename.

        :param rolename: The name of the new role.
        """
        query = "CREATE ROLE {}"
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(rolename)))
            logger.info("Created role %s", rolename)
        except Exception as err:
            logger.error("Failed to create role %s: %s", rolename, err)
            raise err

    def drop_role(self, rolename: str) -> None:
        """
        Drops an existing PostgreSQL role with the specified rolename.

        :param rolename: The name of the role to drop.
        """
        query = "DROP ROLE IF EXISTS {}"
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(rolename)))
            logger.info("Dropped role %s", rolename)
        except Exception as err:
            logger.error("Failed to drop role %s: %s ", rolename, err)
            raise err

    def add_user_to_role(self, rolename: str, username: str) -> None:
        """
        Adds a PostgreSQL user with the specified username to an existing PostgreSQL role with the specified rolename.

        :param rolename: The name of the role to add the user to.
        :param username: The username of the user to add to the role.
        """
        query = "GRANT {} TO {}"
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(rolename), sql.Identifier(username)))
            logger.info("Added user %s to role %s", username, rolename)
        except Exception as err:
            logger.error("Failed to add user %s to role %s: %s", username, rolename, err)
            raise err

    def check_user_exists(self, username: str) -> bool:
        """
        Checks if a PostgreSQL user with the specified username exists.

        :param username: The username of the user to check.
        :return: True if the user exists, False otherwise.
        """
        query = "SELECT 1 FROM pg_roles WHERE rolname=%s"
        try:
            result = self.conn.execute(query, (username,)).fetchone()
            return bool(result)
        except Exception as err:
            logger.error("Failed to check if user %s exists: %s", username, err)
            raise err

    def return_user_info(self, username: str) -> List[Tuple]:
        """
        Returns information about a PostgreSQL user with the specified username.

        :param username: The username of the user to return information for.
        :return: A list of tuples containing the user's attributes.
        """
        query = """
                SELECT r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb, 
                    r.rolcanlogin, r.rolreplication, r.rolconnlimit, a.rolpassword, 
                    r.rolvaliduntil, r.rolbypassrls, r.rolconfig 
                FROM pg_roles as r
                INNER JOIN pg_authid as a ON r.oid = a.oid   
                WHERE r.rolname=%s
                """
        try:
            with self.conn.cursor(row_factory=dict_row) as cur:
                result = cur.execute(query, (username,)).fetchall()
                return result
        except Exception as err:
            logger.error("Failed to return info for user %s: %s", username, err)
            raise err

    def add_users_to_role(self, rolename: str, usernames: List[str]) -> None:
        """
        Adds one or more PostgreSQL users with the specified usernames to an existing PostgreSQL role with the specified rolename.

        :param rolename: The name of the role to add users to.
        :param usernames: The usernames of the users to add to the role.
        """
        for username in usernames:
            self.add_user_to_role(rolename, username)

    def remove_user_from_role(self, rolename: str, username: str) -> None:
        """
        Removes one or more PostgreSQL users with the specified usernames from an existing PostgreSQL role with the specified rolename.

        :param rolename: The name of the role to remove users from.
        :param usernames: The usernames of the users to remove from the role.
        """
        query = "REVOKE {} FROM {}"
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(rolename), sql.Identifier(username)))
            logger.info("Removed user %s from role %s", username, rolename)
        except Exception as err:
            logger.error("Failed to remove user %s from role %s: %s", username, rolename, err)
            raise err

    def remove_users_from_role(self, rolename: str, usernames: List[str]) -> None:
        """
        Removes one or more PostgreSQL users with the specified usernames from an existing PostgreSQL role with the specified rolename.

        :param rolename: The name of the role to remove users to.
        :param usernames: The usernames of the users to remove from the role.
        """
        for username in usernames:
            self.remove_user_from_role(rolename, username)

    def grant_database_permissions_to_role(self, rolename: str, database: str, permissions: str) -> None:
        """
        Grants the specified permissions on the specified database to an existing PostgreSQL role with the specified rolename.

        :param rolename: The name of the role to grant permissions to.
        :param database: The name of the database to grant permissions on.
        :param permissions: The permissions to grant.
        """
        if permissions.upper() == 'ALL':
            permissions = 'ALL PRIVILEGES'
        query = "GRANT {} ON DATABASE {} TO {}"
        try:
            self.conn.execute(
                sql.SQL(query).format(
                    sql.SQL(parse_options(permissions, 'database', ',')),  # type: ignore
                    sql.Identifier(database),
                    sql.Identifier(rolename),
                )
            )
            logger.info("Granted %s permissions on database %s to role %s", permissions, database, rolename)
        except Exception as err:
            logger.error(
                "Failed to grant %s permissions on database %s to role %s: %s", permissions, database, rolename, err
            )
            raise err

    def revoke_database_permissions_from_role(self, rolename: str, database: str, permissions: str) -> None:
        """
        Revokes the specified permissions on the specified database from an existing PostgreSQL role with the specified rolename.

        :param rolename: The name of the role to revoke permissions from.
        :param database: The name of the database to revoke permissions on.
        :param permissions: The permissions to revoke.
        """
        if permissions.upper() == 'ALL':
            permissions = 'ALL PRIVILEGES'
        query = "REVOKE {} ON DATABASE {} FROM {}"
        try:
            self.conn.execute(
                sql.SQL(query).format(
                    sql.SQL(parse_options(permissions, 'database', ',')),  # type: ignore
                    sql.Identifier(database),
                    sql.Identifier(rolename),
                )
            )
            logger.info("Revoked %s permissions on database %s from role %s", permissions, database, rolename)
        except Exception as err:
            logger.error(
                "Failed to revoke %s permissions on database %s from role %s: %s", permissions, database, rolename, err
            )
            raise err

    # ToDo: Add support for object-level permissions and default privileges
