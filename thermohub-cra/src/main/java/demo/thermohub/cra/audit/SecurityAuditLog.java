package demo.thermohub.cra.audit;

import java.time.Clock;
import java.time.Instant;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.MeterRegistry;

/**
 * A09:2025 Security Logging & Alerting Failures → CRA Annex I Part I (2)(l) and Article 14.
 * <p>
 * Every security-relevant decision becomes (1) a structured log event (ECS JSON, ready for the SIEM),
 * (2) a metric {@code thermohub.security.events{type=...}} to alert on, and (3) an entry in a small
 * in-memory ring buffer exposed to administrators. Detection is the precondition for the 24-hour
 * early warning to ENISA's Single Reporting Platform.
 */
@Component
public class SecurityAuditLog {

    private static final Logger log = LoggerFactory.getLogger("SECURITY_AUDIT");
    private static final int CAPACITY = 500;

    private final Deque<SecurityEvent> recent = new ConcurrentLinkedDeque<>();
    private final ObjectProvider<MeterRegistry> meters;
    private final Clock clock = Clock.systemUTC();

    public SecurityAuditLog(ObjectProvider<MeterRegistry> meters) {
        this.meters = meters;
    }

    public void record(SecurityEventType type, String principal, String subject) {
        SecurityEvent event = new SecurityEvent(Instant.now(clock), type, principal, subject);
        recent.addFirst(event);
        while (recent.size() > CAPACITY) {
            recent.pollLast();
        }
        log.atWarn()
                .addKeyValue("event.action", type.name())
                .addKeyValue("user.name", principal)
                .addKeyValue("thermohub.subject", subject)
                .log("security event {}", type);
        meters.ifAvailable(registry -> registry.counter("thermohub.security.events", "type", type.name()).increment());
    }

    public List<SecurityEvent> recent() {
        return List.copyOf(recent);
    }
}
