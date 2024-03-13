CREATE TABLE IF NOT EXISTS account (
     id VARBINARY(16) PRIMARY KEY,
     email VARCHAR(255),
     password VARCHAR(255),
     role_id INT,
     campus_id INT,
     student_id VARBINARY(16),
     instructor_id VARBINARY(16),
     system_user_id VARBINARY(16),
     create_at DATETIME NOT NULL,
     update_at DATETIME NOT NULL
);