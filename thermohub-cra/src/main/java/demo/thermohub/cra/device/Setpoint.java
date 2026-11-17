package demo.thermohub.cra.device;

import java.math.BigDecimal;
import java.math.RoundingMode;

import demo.thermohub.cra.common.InvalidInputException;

/**
 * A06:2025 Insecure Design → fixed in the model, not at the edge.
 * <p>
 * Risk assessment (Art. 13(2), docs/cra/risk-assessment.md, THREAT-07): a remote attacker or a buggy
 * client must not be able to drive the heating outside a safe physical range. The rule lives in a
 * domain primitive, so every code path – REST, MQTT, schedules – gets it for free.
 */
public record Setpoint(BigDecimal celsius) {

    public static final BigDecimal MIN = new BigDecimal("5.0");
    public static final BigDecimal MAX = new BigDecimal("30.0");

    public Setpoint {
        if (celsius == null || celsius.compareTo(MIN) < 0 || celsius.compareTo(MAX) > 0) {
            throw new InvalidInputException("Setpoint must be between 5.0 and 30.0 °C");
        }
        celsius = celsius.setScale(1, RoundingMode.HALF_UP);
    }
}
