
CREATE TABLE IF NOT EXISTS User (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL,
    role TEXT NOT NULL
);

-- adds testing user and admin 
INSERT INTO User (username, email, password, role) VALUES ('admin', 'admin@admin.com', 'pbkdf2:sha256:1000000$ySCTlfy4eDSj826r$a375d2a73b62f3af9921cc218682f20f0c2208bb3a38f607a0c6b6daa9966e1a', 'Admin');
INSERT INTO User (username, email, password, role) VALUES ('user', 'user@user.com', 'pbkdf2:sha256:1000000$ySCTlfy4eDSj826r$a375d2a73b62f3af9921cc218682f20f0c2208bb3a38f607a0c6b6daa9966e1a', 'User');

-- activity table 
CREATE TABLE IF NOT EXISTS activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    action TEXT NOT NULL,
    page TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT
);

--failed login 
CREATE TABLE IF NOT EXISTS access_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    ip_address TEXT
);
--devices 
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tuya_device_id TEXT NOT NULL UNIQUE, 
    name TEXT NOT NULL, 
    assigned_user_id INTEGER, 
    FOREIGN KEY (assigned_user_id) REFERENCES User (id) ON DELETE SET NULL
);


