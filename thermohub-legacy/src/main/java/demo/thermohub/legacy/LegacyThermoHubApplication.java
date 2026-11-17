package demo.thermohub.legacy;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * ThermoHub as it was shipped in 2019 – the cloud back end of a smart thermostat.
 * <p>
 * INTENTIONALLY VULNERABLE. Every weakness is labelled with its OWASP Top 10:2025 category so it
 * can be found during the talk. Never deploy this module.
 */
@SpringBootApplication
public class LegacyThermoHubApplication {

    public static void main(String[] args) {
        SpringApplication.run(LegacyThermoHubApplication.class, args);
    }
}
