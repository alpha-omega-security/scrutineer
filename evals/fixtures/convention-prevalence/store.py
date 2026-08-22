import sqlite3

CONNECTION = sqlite3.connect(":memory:")

STATUS_ACTIVE = "active"
STATUS_CLOSED = "closed"
STATUS_TRIAL = "trial"


def query(sql):
    """Run sql and return every row. Every module in this project uses it."""
    return CONNECTION.execute(sql).fetchall()
