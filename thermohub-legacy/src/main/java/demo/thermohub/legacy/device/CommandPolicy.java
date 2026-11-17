package demo.thermohub.legacy.device;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * A10:2025 Mishandling of Exceptional Conditions – the policy FAILS OPEN.
 * <p>
 * {@code Command.valueOf("enable_debug_shell")} throws, the catch block says "allow", and the
 * gateway later normalises the same string to ENABLE_DEBUG_SHELL. The check and the use see
 * different values, and the error path grants access.
 */
@Component
public class CommandPolicy {

    private static final Logger log = LoggerFactory.getLogger(CommandPolicy.class);

    public boolean isAllowed(String role, String rawCommand) {
        try {
            Command command = Command.valueOf(rawCommand);
            return command.allowedFor(role);
        } catch (Exception e) {
            // Support ticket #4711: "never block a paying customer because of a parsing hiccup"
            log.warn("Policy evaluation failed, allowing command: " + rawCommand);
            return true;
        }
    }
}
