package demo.thermohub.cra;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;

/** A07 → CRA Annex I Part I (2)(b): the product does not start with a missing or default admin password. */
class NoDefaultCredentialsTest {

    @Test
    @DisplayName("start-up fails without an administrator passphrase")
    void refusesToStartWithoutAdminPassword() {
        assertThatThrownBy(() -> start(""))
                .hasStackTraceContaining("No default credentials");
    }

    @Test
    @DisplayName("start-up fails with the factory default admin/admin")
    void refusesToStartWithFactoryDefault() {
        assertThatThrownBy(() -> start("admin"))
                .hasStackTraceContaining("No default credentials");
    }

    private static void start(String adminPassword) {
        String throwAwayDataKey = Base64.getEncoder().encodeToString(new byte[32]);
        // Command-line args outrank application.properties and the environment; builder.properties() would not.
        new SpringApplicationBuilder(ThermoHubApplication.class)
                .run(
                        "--server.port=0",
                        "--spring.main.banner-mode=off",
                        "--thermohub.demo.enabled=false",
                        "--thermohub.admin.password=" + adminPassword,
                        "--thermohub.crypto.wifi.key=" + throwAwayDataKey)
                .close();
    }
}
