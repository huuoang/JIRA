-- Create Campus table
CREATE TABLE IF NOT EXISTS campus (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    location VARCHAR(255) NOT NULL,
    create_at DATETIME NOT NULL,
    update_at DATETIME NOT NULL
);