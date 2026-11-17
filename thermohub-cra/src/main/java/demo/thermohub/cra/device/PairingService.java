package demo.thermohub.cra.device;

import java.util.Optional;

import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import demo.thermohub.cra.audit.SecurityAuditLog;
import demo.thermohub.cra.audit.SecurityEventType;
import demo.thermohub.cra.security.AttemptLimiter;
import demo.thermohub.cra.web.RejectedRequestException;

/**
 * A06:2025 Insecure Design → fixed by design, not by a patch:
 * <ul>
 *   <li>8-character code from a CSPRNG (about 40 bits) instead of 4 digits (about 13 bits),</li>
 *   <li>stored as a bcrypt hash, compared by the password encoder,</li>
 *   <li>5 failed attempts per device per 15 minutes, then HTTP 429,</li>
 *   <li>every failure and every throttle is a security event.</li>
 * </ul>
 */
@Service
public class PairingService {

    private final DeviceRepository devices;
    private final PasswordEncoder encoder;
    private final AttemptLimiter limiter;
    private final SecurityAuditLog audit;

    public PairingService(DeviceRepository devices, PasswordEncoder encoder, AttemptLimiter limiter, SecurityAuditLog audit) {
        this.devices = devices;
        this.encoder = encoder;
        this.limiter = limiter;
        this.audit = audit;
    }

    public Device pair(String serial, String code, String user) {
        String key = "pair:" + serial;
        if (limiter.isBlocked(key)) {
            audit.record(SecurityEventType.PAIRING_THROTTLED, user, serial);
            throw new RejectedRequestException(HttpStatus.TOO_MANY_REQUESTS, "Too many pairing attempts – try again later");
        }
        Optional<String> codeHash = devices.pairingCodeHashOfUnpaired(serial);
        boolean matches = codeHash.map(hash -> encoder.matches(code, hash)).orElse(false);
        if (!matches || !devices.assignOwner(serial, user)) {
            limiter.recordFailure(key);
            audit.record(SecurityEventType.PAIRING_FAILED, user, serial);
            throw new RejectedRequestException(HttpStatus.BAD_REQUEST, "Pairing failed");
        }
        limiter.reset(key);
        audit.record(SecurityEventType.DEVICE_PAIRED, user, serial);
        return devices.findBySerial(serial).orElseThrow();
    }
}
