package demo.thermohub.cra.device;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Pretends to push a command to the thermostat over MQTT. Accepts only the typed {@link Command}:
 * the value that was authorised is, by construction, the value that is executed.
 */
@Component
public class DeviceGateway {

    private static final Logger log = LoggerFactory.getLogger(DeviceGateway.class);

    public String send(Device device, Command command) {
        log.info(">>> MQTT thermohub/{}/cmd : {}", device.serial(), command);
        return command.name();
    }
}
