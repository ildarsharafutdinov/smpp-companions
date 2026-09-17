CREATE TABLE front_bearer_dlr (
    smsc VARCHAR,
    timestamp VARCHAR,
    destination VARCHAR,
    source VARCHAR,
    service VARCHAR,
    url VARCHAR,
    mask VARCHAR,
    status VARCHAR,
    boxc_id VARCHAR
);

CREATE TABLE smsc_bearer_dlr (
    smsc VARCHAR,
    timestamp VARCHAR,
    destination VARCHAR,
    source VARCHAR,
    service VARCHAR,
    url VARCHAR,
    mask VARCHAR,
    status VARCHAR,
    boxc_id VARCHAR
);

CREATE TABLE smsc_smpp_dlr (
    oid BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    smsc VARCHAR,
    timestamp VARCHAR,
    destination VARCHAR,
    source VARCHAR,
    service VARCHAR,
    url VARCHAR,
    mask VARCHAR,
    status VARCHAR,
    boxc_id VARCHAR
);