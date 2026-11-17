package demo.thermohub.legacy.device;

public enum Command {

    REBOOT("USER"),
    ECO_MODE_ON("USER"),
    ECO_MODE_OFF("USER"),
    FACTORY_RESET("ADMIN"),
    ENABLE_DEBUG_SHELL("ADMIN");

    private final String minimumRole;

    Command(String minimumRole) {
        this.minimumRole = minimumRole;
    }

    boolean allowedFor(String role) {
        return "ADMIN".equals(role) || minimumRole.equals(role);
    }
}
