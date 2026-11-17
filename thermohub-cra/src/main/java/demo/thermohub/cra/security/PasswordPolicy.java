package demo.thermohub.cra.security;

import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

/**
 * A07:2025 Authentication Failures – no default or weak bootstrap credentials.
 * <p>
 * Length over complexity, following NIST SP 800-63B-4 for single-factor passwords (15 characters),
 * plus a small deny list. In production, add a breached-password check
 * (Spring Security's {@code CompromisedPasswordChecker}).
 */
public final class PasswordPolicy {

    public static final int MIN_LENGTH = 15;

    private static final Set<String> DENY_LIST = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);

    static {
        DENY_LIST.addAll(List.of(
                "admin", "administrator", "password", "changeme", "default", "letmein", "welcome",
                "123456", "12345678", "123456789", "qwerty", "thermohub", "summer2026"));
    }

    private PasswordPolicy() {
    }

    public static List<String> violations(String username, String candidate) {
        List<String> problems = new ArrayList<>();
        if (candidate == null || candidate.isBlank()) {
            problems.add("no password configured");
            return problems;
        }
        if (candidate.length() < MIN_LENGTH) {
            problems.add("shorter than " + MIN_LENGTH + " characters");
        }
        if (DENY_LIST.contains(candidate)) {
            problems.add("on the deny list of common passwords");
        }
        if (username != null && !username.isBlank()
                && Pattern.compile(Pattern.quote(username), Pattern.CASE_INSENSITIVE).matcher(candidate).find()) {
            problems.add("contains the user name");
        }
        return problems;
    }

    /** Fails fast at start-up – the product never runs with a factory default credential. */
    public static void requireCompliant(String username, String candidate, String setting) {
        List<String> problems = violations(username, candidate);
        if (!problems.isEmpty()) {
            throw new IllegalStateException("No default credentials (CRA Annex I Part I (2)(b)): " + setting
                    + " for '" + username + "' is " + String.join(", ", problems) + ".");
        }
    }
}
