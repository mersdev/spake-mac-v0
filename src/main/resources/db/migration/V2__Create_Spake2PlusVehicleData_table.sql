CREATE SEQUENCE SPAKE_VEHICLE_SEQ START WITH 1 INCREMENT BY 1;

CREATE TABLE spake2_plus_vehicle_data (
    id BIGINT PRIMARY KEY,
    request_id VARCHAR(255),
    w0 NUMERIC NULL,
    w1 NUMERIC NULL
);