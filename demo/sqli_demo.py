"""Classroom demo: why string-built SQL is vulnerable and parameterized SQL is not.
Runs entirely on an in-memory SQLite database; it does not touch the portal.

    python demo/sqli_demo.py
"""
import sqlite3

db = sqlite3.connect(":memory:")
db.execute("CREATE TABLE users (username TEXT, password TEXT)")
db.execute("INSERT INTO users VALUES ('asha', 'Secret123')")

def vulnerable_login(username, password):
    # BAD: user input is pasted into the SQL text
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    print("   SQL sent  :", query)
    return db.execute(query).fetchone() is not None

def safe_login(username, password):
    # GOOD: ? placeholders keep input as data, never as SQL
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    print("   SQL sent  :", query, (username, password))
    return db.execute(query, (username, password)).fetchone() is not None

for label, fn in (("VULNERABLE (string concatenation)", vulnerable_login),
                  ("SECURE (parameterized query)", safe_login)):
    print("\n" + label)
    for u, p in (("asha", "Secret123"), ("asha", "wrong"), ("' OR '1'='1", "' OR '1'='1"), ("asha'--", "x")):
        print(f" login({u!r}, {p!r})")
        print("   result    :", "LOGGED IN" if fn(u, p) else "rejected")
print("\nThe portal itself never builds SQL from input: see the ? placeholders in app.py.")
