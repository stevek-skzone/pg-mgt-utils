"""Main module."""
import logging
import psycopg2
from .pg_role import PgRole


logger = logging.getLogger(__name__)


class PgClient:
    def __init__(self, host, port, user, password, database):
        self.url = f'postgresql://{user}:{password}@{host}/{database}'
        self.autocommit = True
        self.conn = psycopg2.connect(self.url)
        self.conn.autocommit = self.autocommit


    def execute_query(self, query):
        with self.conn.cursor() as cur:
            cur.execute(query)
            result = cur.fetchall()
        return result

    def close_connection(self):
        self.conn.close()

