package demo.thermohub.cra.audit;

import java.time.Instant;

public record SecurityEvent(Instant time, SecurityEventType type, String principal, String subject) {
}
