-- Bell-LaPadula Model Database Schema
-- SQLite3

PRAGMA foreign_keys = ON;
PRAGMA journal_mode = WAL;

-- Users table with hashed passwords
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER  PRIMARY KEY AUTOINCREMENT,
    username      TEXT     NOT NULL UNIQUE,
    password_hash TEXT     NOT NULL,
    display_name  TEXT     NOT NULL,
    level         INTEGER  NOT NULL CHECK(level IN (1,2,3,4)),
    role          TEXT     NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
    status        TEXT     NOT NULL DEFAULT 'pending' CHECK(status IN ('active','pending','suspended')),
    created_at    DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_login    DATETIME
);

-- Classification levels reference table
CREATE TABLE IF NOT EXISTS classification_levels (
    level     INTEGER PRIMARY KEY,
    name      TEXT    NOT NULL,
    label     TEXT    NOT NULL,
    color_hex TEXT    NOT NULL
);

-- Files / documents  (content + images stored directly in DB)
CREATE TABLE IF NOT EXISTS files (
    id          INTEGER  PRIMARY KEY AUTOINCREMENT,
    name        TEXT     NOT NULL,
    file_type   TEXT     NOT NULL DEFAULT 'doc',
    level       INTEGER  NOT NULL REFERENCES classification_levels(level),
    owner_id    INTEGER  NOT NULL REFERENCES users(id),
    content     TEXT     NOT NULL DEFAULT '',
    images      TEXT     NOT NULL DEFAULT '[]',   -- JSON array of base64 strings
    created_at  DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at  DATETIME
);

-- Secure channel messages  (BLP-filtered on read)
CREATE TABLE IF NOT EXISTS messages (
    id         INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER  NOT NULL REFERENCES users(id),
    content    TEXT     NOT NULL,
    level      INTEGER  NOT NULL REFERENCES classification_levels(level),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Audit log — every access attempt stored permanently
CREATE TABLE IF NOT EXISTS audit_log (
    id           INTEGER  PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER  REFERENCES users(id),
    action       TEXT     NOT NULL,
    target       TEXT     NOT NULL,
    target_level INTEGER  REFERENCES classification_levels(level),
    allowed      INTEGER  NOT NULL CHECK(allowed IN (0,1)),
    reason       TEXT,
    ip_address   TEXT,
    created_at   DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Seed classification levels
INSERT OR IGNORE INTO classification_levels VALUES (1,'Public',       'PUBLIC',       '#457b9d');
INSERT OR IGNORE INTO classification_levels VALUES (2,'Confidential', 'CONFIDENTIAL', '#2a9d8f');
INSERT OR IGNORE INTO classification_levels VALUES (3,'Secret',       'SECRET',       '#f4a261');
INSERT OR IGNORE INTO classification_levels VALUES (4,'Top Secret',   'TOP SECRET',   '#e63946');
