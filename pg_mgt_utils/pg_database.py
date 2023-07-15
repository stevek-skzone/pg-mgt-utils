# pylint: disable=line-too-long
from typing import Any, Dict, List, Optional

from psycopg import sql
from psycopg.rows import dict_row

from pg_mgt_utils.pg_common import logger, validate_encoding


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

    def create_database(
        self,
        dbname: str,
        owner: Optional[str] = None,
        encoding: Optional[str] = None,
        connection_limit: Optional[int] = None,
    ) -> None:
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
            self.conn.execute(sql.SQL(query).format(sql.Identifier(dbname)))  # type: ignore
            logger.info("Created database %s", dbname)
        except Exception as err:
            self.conn.rollback()
            logger.error("Failed to create database %s", dbname)
            raise err

    def drop_database(self, dbname: str) -> None:
        """
        Drops an existing PostgreSQL database with the specified name.

        :param dbname: The name of the database to drop.
        """
        query = "DROP DATABASE IF EXISTS {}"
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(dbname)))
            logger.info("Dropped database %s", dbname)
        except Exception as err:
            self.conn.rollback()
            logger.error("Failed to drop database %s", dbname)
            raise err

    def alter_database(
        self,
        dbname: str,
        owner: Optional[str] = None,
        encoding: Optional[str] = None,
        connection_limit: Optional[int] = None,
    ) -> None:
        """
        Alters an existing PostgreSQL database with the specified name and options.

        :param dbname: The name of the database to create.
        :param owner: The name of the role that will own the new database.
        :param encoding: The character encoding to use for the new database.
        :param connection_limit: The maximum number of concurrent connections allowed for the new database.
        """
        query = "ALTER DATABASE {}"
        if owner:
            query += f' OWNER {sql.Identifier(owner)}'
        if encoding and validate_encoding(encoding):
            query += f' ENCODING \'{encoding}\''
        if connection_limit:
            query += f' CONNECTION LIMIT {connection_limit}'
        try:
            self.conn.execute(sql.SQL(query).format(sql.Identifier(dbname)))  # type: ignore
            logger.info("Altered database %s", dbname)
        except Exception as err:
            self.conn.rollback()
            logger.error("Failed to alter database %s", dbname)
            raise err

    def check_database_exists(self, dbname: str) -> bool:
        """
        Checks if a PostgreSQL database with the specified name exists.

        :param dbname: The name of the database to check.
        :return: True if the database exists, False otherwise.
        """
        query = "SELECT COUNT(*) FROM pg_database WHERE datname = %s"
        try:
            result = self.conn.execute(query, (dbname,)).fetchone()
            return bool(result[0])
        except Exception as err:
            logger.error("Failed to check if user %s exists: %s", dbname, err)
            raise err

    def return_database_info(self, dbname: str) -> List[Dict[str, Any]]:
        """
        Returns information about a PostgreSQL database with the specified name.

        :param dbname: The name of the database to return information for.
        :return: A list of dictionaries containing information about the database.
        """
        query = """
            SELECT datname, pg_get_userbyid(datdba) AS owner, pg_encoding_to_char(encoding) AS encoding, datcollate, 
            datctype, datistemplate, datallowconn, datconnlimit, datfrozenxid, datminmxid, dattablespace, datacl
            FROM pg_database WHERE datname = %s
        """
        try:
            with self.conn.cursor(row_factory=dict_row) as cur:
                result = cur.execute(query, (dbname,)).fetchall()
                return result
        except Exception as err:
            logger.error("Failed to return info for database %s: %s", dbname, err)
            raise err
