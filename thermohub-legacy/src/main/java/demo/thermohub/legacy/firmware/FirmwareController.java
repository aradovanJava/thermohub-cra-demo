package demo.thermohub.legacy.firmware;

import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * A08:2025 Software or Data Integrity Failures – whatever bytes an admin account uploads are rolled
 * out to every thermostat. No signature, no provenance, no anti-rollback. One phished admin
 * password (admin/admin, see A07) becomes a botnet.
 */
@RestController
@RequestMapping("/api/admin/firmware")
public class FirmwareController {

    private static final Logger log = LoggerFactory.getLogger(FirmwareController.class);

    private final JdbcTemplate jdbc;

    public FirmwareController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @PostMapping(consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<Map<String, Object>> publish(@RequestHeader("X-Firmware-Version") String version,
                                                       @RequestBody byte[] image) throws Exception {
        String sha256 = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(image));
        jdbc.update("MERGE INTO firmware_releases (version, sha256, rolled_out) KEY (version) VALUES (?, ?, TRUE)",
                version, sha256);
        Integer fleet = jdbc.queryForObject("SELECT COUNT(*) FROM devices", Integer.class);
        log.info("Firmware {} rolled out to {} thermostats", version, fleet);
        return ResponseEntity.accepted().body(Map.of(
                "version", version,
                "sha256", sha256,
                "rolledOutTo", fleet + " thermostats"));
    }
}
