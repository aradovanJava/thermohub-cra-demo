package demo.thermohub.legacy.device;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/** Pretends to push a command to the thermostat over MQTT. */
@Component
public class DeviceGateway {

    private static final Logger log = LoggerFactory.getLogger(DeviceGateway.class);

    /** Normalises the raw string the policy could not parse – and executes it. */
    public String send(Device device, String rawCommand) {
        String command = rawCommand.trim().toUpperCase();
        log.info(">>> MQTT thermohub/{}/cmd : {}", device.serial(), command);
        return command;
    }
}
