-- Idempotente: se puede ejecutar en cada arranque
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- Índices opcionales
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
