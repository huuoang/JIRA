INSERT INTO account (
    id,
    email,
    password,
    campus_id,
    student_id,
    instructor_id,
    system_user_id,
    role_id,
    create_at,
    update_at
) VALUES (
             UUID_TO_BIN(UUID()), 'manhnmhe171616@fpt.edu.vn', '$2a$10$GEQeoTQT0f4KGQtZrqk13.hy5vWwRhdPxMrYm.pYH8vvA/3XaMHBi',
             1, UUID_TO_BIN('367511ac-bf97-11ee-bdb8-106530543950'), null, null, 1,
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
         ),
         (
             UUID_TO_BIN(UUID()), 'cuongvvhe170851@fpt.edu.vn', '$2a$10$0FHtWVa.FgXYABMheN2zmuJ7eNRnouFYJs5OkKV8uUKIDYulXsOXq',
             1, UUID_TO_BIN('ea855438-bfa1-11ee-bdb8-106530543950'), null, null, 4,
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
         ),
         (
             UUID_TO_BIN(UUID()), 'datndhe172134@fpt.edu.vn', '$2a$10$iZAyic9Z/pe/NAKqP7mmveH7XnKvoMaPhse1oiBg6Y08N2mknTT6e',
             1, null, UUID_TO_BIN('cf578b9c-bf92-11ee-bdb8-106530543950'), null, 2,
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
         ),
         (
             UUID_TO_BIN(UUID()), 'hoangnhhe176541@fpt.edu.vn', '$2a$10$ZlrmgxkFTBCi2RbgN.AxZembDzoFbveU51/Tolvcr.fbxsjWIMh/e',
             1, null, null, null, 3,
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
         ),
         (
             UUID_TO_BIN(UUID()), 'viettqhe170367@fpt.edu.vn', '$2a$10$0FHtWVa.FgXYABMheN2zmuJ7eNRnouFYJs5OkKV8uUKIDYulXsOXq',
             1, null, null, null, 4,
             CURRENT_TIMESTAMP, CURRENT_TIMESTAMP
         );
