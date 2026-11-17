package demo.thermohub.cra.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import demo.thermohub.cra.crypto.SecureTokenGenerator;

/**
 * A07:2025 → CRA Annex I Part I (2)(b): there is no factory default account.
 * <p>
 * The administrator password must be supplied at installation time (THERMOHUB_ADMIN_PASSWORD) and
 * must pass {@link PasswordPolicy}; otherwise the product refuses to start. In demo mode two customer
 * accounts are created and the unpaired thermostat gets a random pairing code.
 */
@Component
public class AccountBootstrap implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(AccountBootstrap.class);

    private final JdbcTemplate jdbc;
    private final PasswordEncoder encoder;
    private final SecureTokenGenerator tokens;
    private final String adminPassword;
    private final boolean demo;
    private final String alicePassword;
    private final String bobPassword;

    public AccountBootstrap(JdbcTemplate jdbc, PasswordEncoder encoder, SecureTokenGenerator tokens,
                            @Value("${thermohub.admin.password:}") String adminPassword,
                            @Value("${thermohub.demo.enabled:false}") boolean demo,
                            @Value("${thermohub.demo.alice.password:}") String alicePassword,
                            @Value("${thermohub.demo.bob.password:}") String bobPassword) {
        this.jdbc = jdbc;
        this.encoder = encoder;
        this.tokens = tokens;
        this.adminPassword = adminPassword;
        this.demo = demo;
        this.alicePassword = alicePassword;
        this.bobPassword = bobPassword;
    }

    @Override
    public void run(ApplicationArguments args) {
        PasswordPolicy.requireCompliant("admin", adminPassword, "THERMOHUB_ADMIN_PASSWORD");
        upsert("admin", adminPassword, "ADMIN");

        if (demo) {
            PasswordPolicy.requireCompliant("alice", alicePassword, "thermohub.demo.alice.password");
            PasswordPolicy.requireCompliant("bob", bobPassword, "thermohub.demo.bob.password");
            upsert("alice", alicePassword, "USER");
            upsert("bob", bobPassword, "USER");

            String pairingCode = tokens.newPairingCode();
            jdbc.update("UPDATE devices SET pairing_code = ? WHERE serial = ? AND owner IS NULL",
                    encoder.encode(pairingCode), "TH-0003");
            // In production the code is printed on the device label at manufacturing time.
            log.info("DEMO: pairing code for TH-0003 is {}", pairingCode);
        }
    }

    private void upsert(String username, String password, String role) {
        jdbc.update("MERGE INTO users (username, password_hash, role) KEY (username) VALUES (?, ?, ?)",
                username, encoder.encode(password), role);
    }
}
