-- Users table (already exists)
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    is_admin BOOLEAN DEFAULT 0
);

-- Devices table
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tuya_device_id TEXT NOT NULL UNIQUE, -- Tuya device ID
    name TEXT NOT NULL, -- Device name
    assigned_user_id INTEGER, -- User ID the device is assigned to
    FOREIGN KEY (assigned_user_id) REFERENCES users (id) ON DELETE SET NULL
);