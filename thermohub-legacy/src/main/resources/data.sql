-- A07:2025 Authentication Failures – factory default account admin/admin
-- A04:2025 Cryptographic Failures – unsalted MD5 (admin = "admin", alice = "summer2026", bob = "123456")
INSERT INTO users (username, password_hash, role) VALUES ('admin', '21232f297a57a5a743894a0e4a801fc3', 'ADMIN');
INSERT INTO users (username, password_hash, role) VALUES ('alice', '2e49d77248f05d5b9c0fa6467dc50fea', 'USER');
INSERT INTO users (username, password_hash, role) VALUES ('bob',   'e10adc3949ba59abbe56e057f20f883e', 'USER');

-- A06:2025 Insecure Design – 4-digit pairing code printed on the box
INSERT INTO devices (id, owner, name, serial, firmware, setpoint, pairing_code) VALUES (1, 'alice', 'Living room', 'TH-0001', '2.4.1', 21.5, NULL);
INSERT INTO devices (id, owner, name, serial, firmware, setpoint, pairing_code) VALUES (2, 'bob',   'Bedroom',     'TH-0002', '2.4.1', 19.0, NULL);
INSERT INTO devices (id, owner, name, serial, firmware, setpoint, pairing_code) VALUES (3, NULL,    'Unpaired',    'TH-0003', '2.4.1', 20.0, '4711');

INSERT INTO firmware_releases (version, sha256, rolled_out) VALUES ('2.4.1', '591abe796c8c8ea79ccf36b3cd9683ec33010013c272b048fc5994071996a75c', TRUE);
