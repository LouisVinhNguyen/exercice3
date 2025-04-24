-- SQLite
PRAGMA foreign_keys = ON;

drop TABLE IF EXISTS Users;
drop TABLE IF EXISTS Tickets;

-- Table pour les utilisateurs (utilisateurs, techniciens, administrateurs)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,  -- Sera haché avec bcrypt
    email TEXT NOT NULL UNIQUE,
    role TEXT NOT NULL CHECK (role IN ('user', 'technician', 'admin')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table pour les tickets
CREATE TABLE IF NOT EXISTS tickets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'in progress', 'closed')),
    user_id INTEGER NOT NULL,
    technician_id INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    closed_at TIMESTAMP,
    
    -- Contraintes de clés étrangères
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (technician_id) REFERENCES users(id) ON DELETE SET NULL,
    
    -- Validation pour s'assurer que closed_at est défini seulement si status est 'closed'
    CHECK ((status = 'closed' AND closed_at IS NOT NULL) OR (status != 'closed' AND closed_at IS NULL)),
    
    -- Validation pour s'assurer que closed_at est après created_at si défini
    CHECK (closed_at IS NULL OR closed_at > created_at)
);

