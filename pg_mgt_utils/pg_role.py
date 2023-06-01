import psycopg2


class PgRole:
    def __init__(self, client):
        self.client = client
        self.conn = psycopg2.connect(client.url)

    def create_user(self, username, password, options=None, max_connections=None, expiry=None):
        query = "CREATE USER %s WITH PASSWORD %s"
        params = [username, password]
        if options:
            self.validate_options(options)
            query += ' ' + ' '.join(options)
        if max_connections:
            query += f' CONNECTION LIMIT {max_connections}'
        if expiry:
            query += f' VALID UNTIL \'{expiry}\''
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, tuple(params))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise e

    def drop_user(self, username):
        query = "DROP USER IF EXISTS %s"
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, (username,))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise e

    def alter_user(self, username, password=None, options=None, max_connections=None, expiry=None):
        query = "ALTER USER %s"
        params = [username]
        if password:
            query += f' WITH PASSWORD {password}'
        if options:
            self.validate_options(options)
            query += ' ' + ' '.join(options)
        if max_connections:
            query += f' CONNECTION LIMIT {max_connections}'
        if expiry:
            query += f' VALID UNTIL \'{expiry}\''
        try:
            with self.conn.cursor() as cur:
                cur.execute(query, tuple(params))
            self.conn.commit()
        except Exception as e:
            self.conn.rollback()
            raise e

    def validate_options(self, options):
        invalid_chars = [';', '\n', '\r']
        for option in options:
            for char in invalid_chars:
                if char in option:
                    raise ValueError(f"Invalid character '{char}' in option '{option}'")