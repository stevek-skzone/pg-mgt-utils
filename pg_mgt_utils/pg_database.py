from typing import Any, Optional, List, Tuple, Dict
from psycopg import sql
from pg_mgt_utils.pg_common import logger, parse_options, validate_encoding
from datetime import datetime, timedelta
from psycopg.rows import dict_row



class PgDatabase:
    """
    A class for managing PostgreSQL roles and users.
    """
    def __init__(self, conn: Any):
        """
        Initializes a new instance of the PgRole class.

        :param conn: A psycopg (psycopg3) connection object.
        """
        self.conn = conn

    def create_database(self, dbname: str, owner: Optional[str] = None, 
                        encoding: Optional[str] = None, 
                        connection_limit: Optional[int] = None) -> None:
        """
        Creates a new PostgreSQL database with the specified name and options.

        :param dbname: The name of the database to create.
        :param owner: The name of the role that will own the new database.
        :param encoding: The character encoding to use for the new database.
        :param connection_limit: The maximum number of concurrent connections allowed for the new database.

        """
        query = "CREATE DATABASE {}"
        if owner:
            query += f' OWNER {sql.Identifier(owner)}'
        if encoding and validate_encoding(encoding):
            query += f' ENCODING \'{encoding}\''
        if connection_limit:
            query += f' CONNECTION LIMIT {connection_limit}'
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(dbname)))
            logger.info(f"Created database {dbname}")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"Failed to create database {dbname}")
            raise e

    def drop_database(self, dbname: str) -> None:
        """
        Drops an existing PostgreSQL database with the specified name.

        :param dbname: The name of the database to drop.
        """
        query = "DROP DATABASE IF EXISTS {}"
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(dbname)))
            logger.info(f"Dropped database {dbname}")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"Failed to drop database {dbname}")
            raise e

    def alter_database(self, dbname: str, owner: Optional[str] = None, 
                        encoding: Optional[str] = None, 
                        connection_limit: Optional[int] = None) -> None:
        """
        Alters an existing PostgreSQL database with the specified name and options.

        :param dbname: The name of the database to create.
        :param owner: The name of the role that will own the new database.
        :param encoding: The character encoding to use for the new database.
        :param connection_limit: The maximum number of concurrent connections allowed for the new database.
        """
        if owner:
            query += f' OWNER {sql.Identifier(owner)}'
        if encoding and validate_encoding(encoding):
            query += f' ENCODING \'{encoding}\''
        if connection_limit:
            query += f' CONNECTION LIMIT {connection_limit}'
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(dbname)))
            logger.info(f"Altered database {dbname}")
        except Exception as e:
            self.conn.rollback()
            logger.error(f"Failed to alter database {dbname}")
            raise e

    def check_database_exists(self, dbname: str) -> bool:
        """
        Checks if a PostgreSQL database with the specified name exists.

        :param dbname: The name of the database to check.
        :return: True if the database exists, False otherwise.
        """
        query = "SELECT COUNT(*) FROM pg_database WHERE datname = %s"
        try:
            result = self.conn.execute(query, (dbname,)).fetchone()
            return bool(result)
        except Exception as e:
            logger.error(f"Failed to check if user {dbname} exists: {e}")
            raise e

    def return_database_info(self, dbname: str) -> List[Dict[str, Any]]:
        """
        Returns information about a PostgreSQL database with the specified name.

        :param dbname: The name of the database to return information for.
        :return: A list of dictionaries containing information about the database.
        """
        query = """
            SELECT datname, pg_encoding_to_char(encoding) AS encoding, datcollate, datctype, datistemplate,
            datallowconn, datconnlimit, datlastsysoid, datfrozenxid, datminmxid, dattablespace, datacl
            FROM pg_database WHERE datname = %s
        """
        try:
            with self.conn.cursor(row_factory=dict_row) as cur:
                result = cur.execute(query, (dbname, )).fetchall()
                return result
        except Exception as e:
            logger.error(f"Failed to return info for database {dbname}: {e}")
            raise e