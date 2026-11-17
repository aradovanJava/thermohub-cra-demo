-- Accounts are NOT seeded here: AccountBootstrap creates them from secrets supplied at installation
-- time and refuses factory defaults (A07, CRA Annex I Part I (2)(b)).
-- The pairing code for TH-0003 is generated at start-up and stored as a bcrypt hash (A04, A06).
INSERT INTO devices (id, owner, name, serial, firmware, setpoint, pairing_code) VALUES (1, 'alice', 'Living room', 'TH-0001', '2.4.1', 21.5, NULL);
INSERT INTO devices (id, owner, name, serial, firmware, setpoint, pairing_code) VALUES (2, 'bob',   'Bedroom',     'TH-0002', '2.4.1', 19.0, NULL);
INSERT INTO devices (id, owner, name, serial, firmware, setpoint, pairing_code) VALUES (3, NULL,    'Unpaired',    'TH-0003', '2.4.1', 20.0, NULL);

INSERT INTO firmware_releases (version, sha256, rolled_out) VALUES ('2.4.1', '591abe796c8c8ea79ccf36b3cd9683ec33010013c272b048fc5994071996a75c', TRUE);
