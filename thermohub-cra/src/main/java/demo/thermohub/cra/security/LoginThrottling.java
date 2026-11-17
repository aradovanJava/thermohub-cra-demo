package demo.thermohub.cra.security;

import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.stereotype.Component;

import demo.thermohub.cra.audit.SecurityAuditLog;
import demo.thermohub.cra.audit.SecurityEventType;

/** A07:2025 – counts failed logins per account and records them as security events (A09). */
@Component
public class LoginThrottling {

    private final AttemptLimiter limiter;
    private final SecurityAuditLog audit;

    public LoginThrottling(AttemptLimiter limiter, SecurityAuditLog audit) {
        this.limiter = limiter;
        this.audit = audit;
    }

    static String key(String username) {
        return "login:" + username;
    }

    @EventListener
    public void onBadCredentials(AuthenticationFailureBadCredentialsEvent event) {
        String username = event.getAuthentication().getName();
        limiter.recordFailure(key(username));
        audit.record(SecurityEventType.LOGIN_FAILED, username, "http-basic");
    }

    @EventListener
    public void onLocked(AuthenticationFailureLockedEvent event) {
        audit.record(SecurityEventType.LOGIN_BLOCKED, event.getAuthentication().getName(), "account temporarily locked");
    }

    @EventListener
    public void onSuccess(AuthenticationSuccessEvent event) {
        limiter.reset(key(event.getAuthentication().getName()));
    }
}
