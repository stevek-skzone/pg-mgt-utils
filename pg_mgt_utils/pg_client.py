"""Main module."""

from datetime import datetime
from typing import Any, Dict, List, Optional

import psycopg
from psycopg.rows import dict_row

from .pg_database import PgDatabase
from .pg_role import PgRole


class PgClient:
    """A PostgreSQL client for executing queries and managing roles and databases.

    Attributes:
        url (str): The connection URL for the PostgreSQL server.
        autocommit (bool): Whether to automatically commit transactions.
        conn (psycopg2.extensions.connection): The connection object for the PostgreSQL server.
        role (PgRole): The role manager for the PostgreSQL server.
        database (PgDatabase): The database manager for the PostgreSQL server.
    """

    def __init__(self, host: str, user: str, password: str, database: str) -> None:
        """Initializes a new instance of the PgClient class.

        Args:
            host (str): The hostname or IP address of the PostgreSQL server.
            user (str): The username to use for authentication.
            password (str): The password to use for authentication.
            database (str): The name of the database to connect to.
        """
        self.url = f'postgresql://{user}:{password}@{host}/{database}?target_session_attrs=primary&application_name=pg_mgt_utils&sslmode=prefer'
        self.autocommit = True
        self.conn = psycopg.connect(self.url)
        self.conn.autocommit = self.autocommit
        self.role = PgRole(self.conn)
        self.database = PgDatabase(self.conn)

    def execute_query(self, query: str) -> List[Any]:
        """Executes a query and returns the results."""
        with self.conn.cursor(row_factory=dict_row) as cur:
            try:
                cur.execute(query)  # type: ignore
            except Exception as err:
                pass
            if cur.description:
                result = cur.fetchall()
            else:
                result = []
        return result

    def close_connection(self) -> None:
        self.conn.close()

    def create_user(
        self,
        username: str,
        password: str,
        options: Optional[str] = None,
        max_connections: Optional[int] = None,
        expiry: Optional[datetime] = None,
    ) -> None:
        self.role.create_user(username, password, options, max_connections, expiry)

    def drop_user(self, username: str) -> None:
        self.role.drop_user(username)

    def alter_user(
        self,
        username: str,
        password: Optional[str] = None,
        options: Optional[str] = None,
        max_connections: Optional[int] = None,
        expiry: Optional[datetime] = None,
    ) -> None:
        self.role.alter_user(username, password, options, max_connections, expiry)

    def create_role(self, rolename: str) -> None:
        self.role.create_role(rolename)

    def drop_role(self, rolename: str) -> None:
        self.role.drop_role(rolename)

    def add_users_to_role(self, rolename: str, usernames: List[str]) -> None:
        self.role.add_users_to_role(rolename, usernames)

    def remove_users_from_role(self, rolename: str, usernames: List[str]) -> None:
        self.role.remove_users_from_role(rolename, usernames)

    def grant_database_permissions_to_role(self, rolename: str, database: str, permissions: str) -> None:
        self.role.grant_database_permissions_to_role(rolename, database, permissions)

    def revoke_database_permissions_from_role(self, rolename: str, database: str, permissions: str) -> None:
        self.role.revoke_database_permissions_from_role(rolename, database, permissions)

    def check_user_exists(self, username: str) -> bool:
        return self.role.check_user_exists(username)

    def return_user_info(self, username: str) -> List[tuple]:
        return self.role.return_user_info(username)

    def create_database(
        self,
        dbname: str,
        owner: Optional[str] = None,
        encoding: Optional[str] = None,
        connection_limit: Optional[int] = None,
    ) -> None:
        self.database.create_database(dbname, owner, encoding, connection_limit)

    def drop_database(self, dbname: str) -> None:
        self.database.drop_database(dbname)

    def alter_database(
        self,
        dbname: str,
        owner: Optional[str] = None,
        encoding: Optional[str] = None,
        connection_limit: Optional[int] = None,
    ) -> None:
        self.database.alter_database(dbname, owner, encoding, connection_limit)

    def check_database_exists(self, dbname: str) -> bool:
        return self.database.check_database_exists(dbname)

    def return_database_info(self, dbname: str) -> List[Dict[str, Any]]:
        return self.database.return_database_info(dbname)
