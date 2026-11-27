-- Defence in depth: the database repeats the whitelist rules from validators.py.
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL CHECK (length(name) BETWEEN 2 AND 60),
    email TEXT NOT NULL UNIQUE,
    roll_number TEXT NOT NULL UNIQUE CHECK (length(roll_number) BETWEEN 10 AND 12),
    branch TEXT NOT NULL CHECK (branch IN ('CSE','IT','ECE','EEE','ME','CE','AIML')),
    semester INTEGER NOT NULL CHECK (semester BETWEEN 1 AND 8),
    gender TEXT NOT NULL CHECK (gender IN ('Male','Female','Other','Prefer not to say')),
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT
);
CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    ip TEXT NOT NULL,
    success INTEGER NOT NULL,
    user_agent TEXT,
    attempted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_attempts ON login_attempts (email, ip, attempted_at);
