package demo.thermohub.cra;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * ThermoHub, retrofitted for the Cyber Resilience Act.
 * <p>
 * Run with the {@code demo} profile for the talk ({@code -Dspring.profiles.active=demo}). Without it,
 * the product refuses to start until real secrets are provided – there are no factory defaults.
 */
@SpringBootApplication
public class ThermoHubApplication {

    public static void main(String[] args) {
        SpringApplication.run(ThermoHubApplication.class, args);
    }
}
