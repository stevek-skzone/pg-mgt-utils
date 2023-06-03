"""Main module."""
import logging
import psycopg2
from psycopg2.extras import DictCursor, DictRow
from typing import List, Any, Tuple, Optional
import os
from .pg_role import PgRole






class PgClient:
    def __init__(self, host: str, user: str, password: str, database: str) -> None:
        self.url = f'postgresql://{user}:{password}@{host}/{database}?target_session_attrs=primary&application_name=pg_mgt_utils&sslmode=prefer'
        self.autocommit = True
        self.conn = psycopg2.connect(self.url)
        self.conn.autocommit = self.autocommit
        self.role = PgRole(self.conn)

    def execute_query(self, query: str) -> List[DictRow]:
        with self.conn.cursor(cursor_factory=DictCursor) as cur:
            cur.execute(query)
            if cur.description:
                result = cur.fetchall()
            else:
                result = []
        return result

    def close_connection(self) -> None:
        self.conn.close()

    def create_user(self, username: str, password: str, options: Optional[str] = None, max_connections: Optional[int] = None, expiry: Optional[str] = None) -> None:
        self.role.create_user(username, password, options, max_connections, expiry)

    def drop_user(self, username: str) -> None:
        self.role.drop_user(username)

    def alter_user(self, username: str, password: Optional[str] = None, options: Optional[str] = None, max_connections: Optional[int] = None, expiry: Optional[str] = None) -> None:
        self.role.alter_user(username, password, options, max_connections, expiry)

    def add_role(self, rolename: str) -> None:
        self.role.add_role(rolename)

    def drop_role(self, rolename: str) -> None:
        self.role.drop_role(rolename)

    def add_users_to_role(self, rolename: str, *usernames: str) -> None:
        self.role.add_users_to_role(rolename, *usernames)

    def remove_users_from_role(self, rolename: str, *usernames: str) -> None:
        self.role.remove_users_from_role(rolename, *usernames)

    def grant_database_permissions_to_role(self, rolename: str, database: str, permissions: str) -> None:
        self.role.grant_database_permissions_to_role(rolename, database, permissions)

    def revoke_database_permissions_from_role(self, rolename: str, database: str, permissions: str) -> None:
        self.role.revoke_database_permissions_from_role(rolename, database, permissions)

    def grant_default_permissions_to_role(self, rolename: str, schema: str, permissions: str) -> None:
        self.role.grant_default_permissions_to_role(rolename, schema, permissions)

    def revoke_default_permissions_from_role(self, rolename: str, schema: str, permissions: str) -> None:
        self.role.revoke_default_permissions_from_role(rolename, schema, permissions)

    def check_user_exists(self, username: str) -> bool:
        return self.role.check_user_exists(username)

    def return_user_info(self, username: str) -> DictRow:
        return self.role.return_user_info(username)