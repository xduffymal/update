import os
import re
import sqlite3


BASE_DIR = os.environ.get('LAB_ROOT', os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "cyber_threat.db")
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema_sqlite.sql")


class SQLiteCursor:
    def __init__(self, cursor, dictionary=False):
        self.cursor = cursor
        self.dictionary = dictionary

    def _convert_sql(self, sql):
        # MySQL placeholders -> SQLite placeholders
        sql = sql.replace("%s", "?")

        # MySQL NOW()
        sql = sql.replace("NOW()", "CURRENT_TIMESTAMP")

        # MySQL DATE_FORMAT -> SQLite strftime
        date_format_pattern = re.compile(
            r"DATE_FORMAT\((.*?),\s*'(%Y-%m-%d %H:%i:%s)'\)",
            re.IGNORECASE
        )

        sql = date_format_pattern.sub(
            r"strftime('%Y-%m-%d %H:%M:%S', \1)",
            sql
        )

        # MySQL 15 minute interval
        sql = re.sub(
            r"\(CURRENT_TIMESTAMP\s*-\s*INTERVAL\s+15\s+MINUTE\)",
            "datetime('now', '-15 minutes')",
            sql,
            flags=re.IGNORECASE
        )

        return sql

    def execute(self, sql, params=()):
        sql = self._convert_sql(sql)
        self.cursor.execute(sql, params)
        return self

    def executemany(self, sql, params):
        sql = self._convert_sql(sql)
        self.cursor.executemany(sql, params)
        return self

    def fetchone(self):
        row = self.cursor.fetchone()

        if row is None:
            return None

        if self.dictionary:
            return dict(row)

        return tuple(row)

    def fetchall(self):
        rows = self.cursor.fetchall()

        if self.dictionary:
            return [dict(row) for row in rows]

        return [tuple(row) for row in rows]

    @property
    def lastrowid(self):
        return self.cursor.lastrowid

    @property
    def description(self):
        return self.cursor.description

    def close(self):
        self.cursor.close()


class SQLiteConnection:
    def __init__(self):
        self.conn = sqlite3.connect(
            DB_PATH,
            check_same_thread=False
        )

        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")

    def cursor(self, dictionary=False):
        return SQLiteCursor(
            self.conn.cursor(),
            dictionary=dictionary
        )

    def commit(self):
        self.conn.commit()

    def rollback(self):
        self.conn.rollback()

    def close(self):
        self.conn.close()

    def execute(self, sql, params=()):
        return self.conn.execute(sql, params)

    def executescript(self, script):
        return self.conn.executescript(script)


def get_db_connection():
    return SQLiteConnection()


def initialize_database():
    conn = sqlite3.connect(DB_PATH)

    conn.execute("PRAGMA foreign_keys = ON")

    with open(SCHEMA_PATH, "r", encoding="utf-8-sig") as file:
        schema = file.read()

    conn.executescript(schema)
    conn.commit()
    conn.close()

    print("Full SQLite capstone database initialized successfully.")


def show_tables():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    rows = conn.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' ORDER BY name"
    ).fetchall()

    print("\nDATABASE TABLES:")

    for row in rows:
        print("-", row["name"])

    conn.close()


def test_database():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row

        result = conn.execute(
            "SELECT COUNT(*) AS user_count FROM users"
        ).fetchone()

        print("\nDATABASE TEST:")
        print("Connection successful.")
        print("Users in database:", result["user_count"])

        conn.close()

    except Exception as error:
        print("\nDATABASE ERROR:")
        print(error)


if __name__ == "__main__":
    initialize_database()
    show_tables()
    test_database()
