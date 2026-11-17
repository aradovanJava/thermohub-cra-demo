CREATE TABLE users (
    username      VARCHAR(50)  PRIMARY KEY,
    password_hash VARCHAR(200) NOT NULL,
    role          VARCHAR(20)  NOT NULL
);

CREATE TABLE devices (
    id           BIGINT       PRIMARY KEY,
    owner        VARCHAR(50),
    name         VARCHAR(200) NOT NULL,
    serial       VARCHAR(20)  NOT NULL UNIQUE,
    firmware     VARCHAR(20)  NOT NULL,
    setpoint     DECIMAL(4,1) NOT NULL,
    pairing_code VARCHAR(200),
    wifi_secret  VARCHAR(500)
);

CREATE TABLE firmware_releases (
    version    VARCHAR(20) PRIMARY KEY,
    sha256     VARCHAR(64) NOT NULL,
    rolled_out BOOLEAN     NOT NULL
);
