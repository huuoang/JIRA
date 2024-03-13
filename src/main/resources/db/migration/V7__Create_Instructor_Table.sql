CREATE TABLE IF NOT EXISTS instructor (
    id VARBINARY(16) PRIMARY KEY,
    email VARCHAR(255),
    username VARCHAR(255),
    first_name VARCHAR(255),
    middle_name VARCHAR(255),
    last_name VARCHAR(255),
    profile_image VARCHAR(255),
    phone VARCHAR(255),
    address VARCHAR(255),
    birth_day DATE,
    id_card VARCHAR(255),
    campus_id BIGINT,
    gender BOOLEAN,
    status BOOLEAN,
    create_at DATETIME,
    update_at DATETIME
);