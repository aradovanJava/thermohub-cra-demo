package demo.thermohub.legacy.device;

import java.math.BigDecimal;

public record Device(long id, String owner, String name, String serial, String firmware, BigDecimal setpoint) {
}
