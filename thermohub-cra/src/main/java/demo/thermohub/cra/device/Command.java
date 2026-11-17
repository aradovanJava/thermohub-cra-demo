package demo.thermohub.cra.device;

import demo.thermohub.cra.common.InvalidInputException;
import demo.thermohub.cra.security.Role;

public enum Command {

    REBOOT(Role.USER),
    ECO_MODE_ON(Role.USER),
    ECO_MODE_OFF(Role.USER),
    FACTORY_RESET(Role.ADMIN),
    ENABLE_DEBUG_SHELL(Role.ADMIN);

    private final Role requiredRole;

    Command(Role requiredRole) {
        this.requiredRole = requiredRole;
    }

    public Role requiredRole() {
        return requiredRole;
    }

    /**
     * A10:2025 fix, part 1 – canonicalise once, then validate against an allowlist.
     * Exact constant names only: no trimming, no case folding, no aliases. Whatever passes here is the
     * same value the policy evaluates and the gateway executes.
     */
    public static Command parse(String raw) {
        for (Command command : values()) {
            if (command.name().equals(raw)) {
                return command;
            }
        }
        throw new InvalidInputException("Unknown command");
    }
}
