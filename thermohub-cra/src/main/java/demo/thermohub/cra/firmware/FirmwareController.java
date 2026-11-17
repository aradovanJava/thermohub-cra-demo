package demo.thermohub.cra.firmware;

import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import demo.thermohub.cra.audit.SecurityAuditLog;
import demo.thermohub.cra.audit.SecurityEventType;
import demo.thermohub.cra.firmware.FirmwareVerifier.Verdict;
import demo.thermohub.cra.web.RejectedRequestException;

/**
 * A08:2025 fix – only firmware signed by the release pipeline's key, newer than the current release,
 * is rolled out. CRA Annex I Part I (2)(c),(f) and Part II (7): updates are distributed securely.
 */
@RestController
@RequestMapping("/api/admin/firmware")
public class FirmwareController {

    private static final int MAX_IMAGE_BYTES = 16 * 1024 * 1024;

    private final JdbcTemplate jdbc;
    private final FirmwareVerifier verifier;
    private final SecurityAuditLog audit;

    public FirmwareController(JdbcTemplate jdbc, FirmwareVerifier verifier, SecurityAuditLog audit) {
        this.jdbc = jdbc;
        this.verifier = verifier;
        this.audit = audit;
    }

    @PostMapping(consumes = MediaType.APPLICATION_OCTET_STREAM_VALUE)
    public ResponseEntity<Map<String, Object>> publish(@RequestHeader("X-Firmware-Version") String versionHeader,
                                                       @RequestHeader(value = "X-Firmware-Signature", required = false) String signature,
                                                       @RequestBody byte[] image,
                                                       Authentication auth) throws Exception {
        if (image.length == 0 || image.length > MAX_IMAGE_BYTES) {
            throw new RejectedRequestException(HttpStatus.BAD_REQUEST, "Firmware image must be 1 byte to 16 MiB");
        }
        FirmwareVersion version = FirmwareVersion.parse(versionHeader);
        Verdict verdict = verifier.verify(version, image, signature, currentRelease());
        if (!verdict.accepted()) {
            audit.record(SecurityEventType.FIRMWARE_REJECTED, auth.getName(), version + ": " + verdict.reason());
            throw new RejectedRequestException(HttpStatus.BAD_REQUEST, verdict.reason());
        }
        String sha256 = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(image));
        jdbc.update("MERGE INTO firmware_releases (version, sha256, rolled_out) KEY (version) VALUES (?, ?, TRUE)",
                version.toString(), sha256);
        audit.record(SecurityEventType.FIRMWARE_RELEASED, auth.getName(), version.toString());
        return ResponseEntity.accepted().body(Map.of("version", version.toString(), "sha256", sha256, "signature", "valid"));
    }

    private FirmwareVersion currentRelease() {
        List<String> versions = jdbc.queryForList("SELECT version FROM firmware_releases WHERE rolled_out = TRUE", String.class);
        return versions.stream().map(FirmwareVersion::parse).max(FirmwareVersion::compareTo).orElse(null);
    }
}
