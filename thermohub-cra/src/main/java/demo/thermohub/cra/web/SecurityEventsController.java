package demo.thermohub.cra.web;

import java.util.List;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import demo.thermohub.cra.audit.SecurityAuditLog;
import demo.thermohub.cra.audit.SecurityEvent;

/** Admin view of recent security events (A09). Production: ship the ECS logs to the SIEM and alert there. */
@RestController
public class SecurityEventsController {

    private final SecurityAuditLog audit;

    public SecurityEventsController(SecurityAuditLog audit) {
        this.audit = audit;
    }

    @GetMapping("/api/admin/security-events")
    public List<SecurityEvent> recentEvents() {
        return audit.recent();
    }
}
