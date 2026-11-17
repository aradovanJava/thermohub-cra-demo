package demo.thermohub.cra.device;

import java.util.Set;

import demo.thermohub.cra.security.Role;

/**
 * A10:2025 fix, part 2 – default deny. The policy works on typed values only and every unexpected
 * condition (null, empty role set, runtime error) ends in DENY. Compare with the legacy policy,
 * whose catch block returned {@code true}.
 */
public final class CommandPolicy {

    public enum Decision { PERMIT, DENY }

    public Decision decide(Set<Role> roles, Command command) {
        try {
            if (roles == null || roles.isEmpty() || command == null) {
                return Decision.DENY;
            }
            boolean permitted = roles.stream().anyMatch(role -> role.satisfies(command.requiredRole()));
            return permitted ? Decision.PERMIT : Decision.DENY;
        } catch (RuntimeException unexpected) {
            return Decision.DENY; // fail closed
        }
    }
}
