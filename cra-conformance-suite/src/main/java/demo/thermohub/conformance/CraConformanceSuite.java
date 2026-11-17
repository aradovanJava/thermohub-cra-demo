package demo.thermohub.conformance;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

/**
 * Executable essential requirements.
 * <p>
 * Every test performs a real OWASP Top 10:2025 attack against the product's HTTP API and asserts
 * the behaviour the Cyber Resilience Act expects. Both products expose the same API, so the same
 * suite runs against the legacy build (expected: red) and the retrofitted build (expected: green).
 * <p>
 * Extend it with {@code @SpringBootTest} in the product module and provide bob's password.
 */
@ExtendWith(CraReportExtension.class)
@TestMethodOrder(MethodOrderer.MethodName.class)
public abstract class CraConformanceSuite {

    protected static final long ALICE_DEVICE = 1L;
    protected static final long BOB_DEVICE = 2L;
    protected static final String UNPAIRED_SERIAL = "TH-0003";

    @Autowired
    private WebApplicationContext context;

    @Autowired
    private JdbcTemplate jdbc;

    protected MockMvc mvc;

    /** Real password of the demo user {@code bob} in the product under test. */
    protected abstract String bobPassword();

    @BeforeEach
    void buildMockMvc() {
        mvc = MockMvcBuilders.webAppContextSetup(context).apply(springSecurity()).build();
    }

    // ------------------------------------------------------------------ A01

    @Test
    @DisplayName("A01 Broken Access Control – a customer cannot read another customer's thermostat")
    @CraRequirement(owasp = "A01:2025 Broken Access Control",
            cra = "Annex I Part I (2)(d)",
            requirement = "Protection from unauthorised access by appropriate control mechanisms")
    void a01_customerCannotReadAnotherCustomersDevice() throws Exception {
        MockHttpServletResponse response = call(get("/api/devices/{id}", BOB_DEVICE).with(alice()));

        assertThat(response.getStatus())
                .as("alice requested bob's device and got HTTP %d: %s", response.getStatus(), abbreviate(response))
                .isIn(403, 404);
    }

    // ------------------------------------------------------------------ A02

    @Test
    @DisplayName("A02 Security Misconfiguration – actuator internals are not exposed")
    @CraRequirement(owasp = "A02:2025 Security Misconfiguration",
            cra = {"Annex I Part I (2)(b)", "Annex I Part I (2)(j)"},
            requirement = "Secure by default configuration; limited attack surface")
    void a02_actuatorInternalsAreNotExposed() throws Exception {
        MockHttpServletResponse response = call(get("/actuator/env"));

        assertThat(response.getStatus())
                .as("anonymous GET /actuator/env returned HTTP %d – configuration and secrets are public", response.getStatus())
                .isNotEqualTo(200);
    }

    @Test
    @DisplayName("A02 Security Misconfiguration – security headers are on by default")
    @CraRequirement(owasp = "A02:2025 Security Misconfiguration",
            cra = "Annex I Part I (2)(b)",
            requirement = "Secure by default configuration")
    void a02_securityHeadersAreOnByDefault() throws Exception {
        MockHttpServletResponse response = call(get("/api/devices").with(alice()));

        assertThat(response.getHeader("X-Content-Type-Options"))
                .as("default security headers were switched off (X-Content-Type-Options missing)")
                .isEqualTo("nosniff");
    }

    // ------------------------------------------------------------------ A03

    @Test
    @DisplayName("A03 Software Supply Chain Failures – YAML import cannot instantiate arbitrary classes")
    @CraRequirement(owasp = "A03:2025 Software Supply Chain Failures",
            cra = {"Annex I Part I (2)(a)", "Annex I Part II (2)"},
            requirement = "No known exploitable vulnerabilities; remediate without delay")
    void a03_yamlImportCannotInstantiateArbitraryClasses() throws Exception {
        Path proof = Path.of("target", "cra-a03-gadget-proof.txt").toAbsolutePath();
        Files.createDirectories(proof.getParent());
        Files.deleteIfExists(proof);
        String gadget = "ecoMode: true\n"
                + "schedule: !!java.io.FileOutputStream [\"" + proof.toString().replace('\\', '/') + "\"]\n";

        MockHttpServletResponse response = call(post("/api/devices/{id}/config", ALICE_DEVICE).with(alice())
                .contentType("application/yaml").content(gadget));

        assertThat(Files.exists(proof))
                .as("CVE-2022-1471 gadget: the YAML import created %s on the server (HTTP %d)", proof.getFileName(), response.getStatus())
                .isFalse();
    }

    // ------------------------------------------------------------------ A04

    @Test
    @DisplayName("A04 Cryptographic Failures – passwords use a modern adaptive hash")
    @CraRequirement(owasp = "A04:2025 Cryptographic Failures",
            cra = "Annex I Part I (2)(e)",
            requirement = "Confidentiality of stored data by state of the art mechanisms")
    void a04_passwordsUseModernAdaptiveHash() {
        String hash = jdbc.queryForObject("SELECT password_hash FROM users WHERE username = ?", String.class, "alice");

        assertThat(hash)
                .as("alice's password is stored as '%s' – an unsalted fast hash is cracked in seconds", hash)
                .matches("^\\{(bcrypt|argon2|pbkdf2|scrypt)(@[^}]*)?}.+");
    }

    // ------------------------------------------------------------------ A05

    @Test
    @DisplayName("A05 Injection – device search is not SQL-injectable")
    @CraRequirement(owasp = "A05:2025 Injection",
            cra = {"Annex I Part I (2)(a)", "Annex I Part I (2)(e)"},
            requirement = "No known exploitable vulnerabilities (CWE-89); data confidentiality")
    void a05_deviceSearchIsNotInjectable() throws Exception {
        String payload = "%' UNION SELECT 0, role, username, password_hash, 'pwned', 0 FROM users -- ";

        MockHttpServletResponse response = call(get("/api/devices/search").param("q", payload).with(alice()));

        assertThat(response.getContentAsString())
                .as("UNION payload dumped the users table: %s", abbreviate(response))
                .doesNotContain("pwned")
                .doesNotContain("bob");
    }

    // ------------------------------------------------------------------ A06

    @Test
    @DisplayName("A06 Insecure Design – the setpoint stays inside the safe physical range")
    @CraRequirement(owasp = "A06:2025 Insecure Design",
            cra = {"Annex I Part I (1)", "Article 13(2)"},
            requirement = "Appropriate cybersecurity based on the risk assessment")
    void a06_setpointStaysInsideSafeRange() throws Exception {
        MockHttpServletResponse response = call(put("/api/devices/{id}/setpoint", ALICE_DEVICE).with(alice())
                .contentType(MediaType.APPLICATION_JSON).content("{\"celsius\": 95.0}"));

        assertThat(response.getStatus())
                .as("the thermostat accepted 95.0 °C (HTTP %d) – the safety limit is missing from the design", response.getStatus())
                .isIn(400, 422);
    }

    @Test
    @DisplayName("A06 Insecure Design – a pairing code cannot be brute-forced")
    @CraRequirement(owasp = "A06:2025 Insecure Design",
            cra = {"Annex I Part I (2)(d)", "Annex I Part I (2)(h)"},
            requirement = "Unauthorised access prevented; resilience against automated attacks")
    void a06_pairingCodeCannotBeBruteForced() throws Exception {
        Integer hijackedAfter = null;
        boolean throttled = false;
        for (int guess = 0; guess <= 9999; guess++) {
            String body = "{\"serial\":\"" + UNPAIRED_SERIAL + "\",\"code\":\"" + String.format("%04d", guess) + "\"}";
            int status = call(post("/api/devices/pair").with(mallory())
                    .contentType(MediaType.APPLICATION_JSON).content(body)).getStatus();
            if (status == 429) {
                throttled = true;
                break;
            }
            if (status >= 200 && status < 300) {
                hijackedAfter = guess + 1;
                break;
            }
        }

        assertThat(hijackedAfter)
                .as("mallory paired %s to her account after %s guesses", UNPAIRED_SERIAL, hijackedAfter)
                .isNull();
        assertThat(throttled)
                .as("10,000 pairing guesses were accepted without throttling")
                .isTrue();
    }

    // ------------------------------------------------------------------ A07

    @Test
    @DisplayName("A07 Authentication Failures – no factory default credentials")
    @CraRequirement(owasp = "A07:2025 Authentication Failures",
            cra = {"Annex I Part I (2)(b)", "Annex I Part I (2)(d)"},
            requirement = "Secure by default; authentication mechanisms")
    void a07_noFactoryDefaultCredentials() throws Exception {
        MockHttpServletResponse response = call(get("/api/devices").with(httpBasic("admin", "admin")));

        assertThat(response.getStatus())
                .as("admin/admin was accepted (HTTP %d)", response.getStatus())
                .isEqualTo(401);
    }

    @Test
    @DisplayName("A07 Authentication Failures – online password guessing is throttled")
    @CraRequirement(owasp = "A07:2025 Authentication Failures",
            cra = "Annex I Part I (2)(d)",
            requirement = "Authentication mechanisms resistant to guessing")
    void a07_onlinePasswordGuessingIsThrottled() throws Exception {
        for (int i = 0; i < 10; i++) {
            call(get("/api/devices").with(httpBasic("bob", "wrong-guess-" + i)));
        }

        MockHttpServletResponse response = call(get("/api/devices").with(httpBasic("bob", bobPassword())));

        assertThat(response.getStatus())
                .as("after 10 wrong guesses the 11th attempt still logged in (HTTP %d)", response.getStatus())
                .isIn(401, 423, 429);
    }

    // ------------------------------------------------------------------ A08

    @Test
    @DisplayName("A08 Software or Data Integrity Failures – unsigned firmware is rejected")
    @CraRequirement(owasp = "A08:2025 Software or Data Integrity Failures",
            cra = {"Annex I Part I (2)(f)", "Annex I Part II (7)"},
            requirement = "Integrity of programs; secure distribution of updates")
    void a08_unsignedFirmwareIsRejected() throws Exception {
        byte[] firmware = "THERMOHUB-FW 9.9.9 (not from our build pipeline)".getBytes(StandardCharsets.UTF_8);

        MockHttpServletResponse response = call(post("/api/admin/firmware").with(admin())
                .header("X-Firmware-Version", "9.9.9")
                .contentType(MediaType.APPLICATION_OCTET_STREAM).content(firmware));

        assertThat(response.getStatus())
                .as("unsigned firmware 9.9.9 was accepted for roll-out (HTTP %d): %s", response.getStatus(), abbreviate(response))
                .isBetween(400, 499);
    }

    // ------------------------------------------------------------------ A09

    @Test
    @DisplayName("A09 Logging & Alerting Failures – control characters cannot forge log entries")
    @CraRequirement(owasp = "A09:2025 Security Logging & Alerting Failures",
            cra = {"Annex I Part I (2)(l)", "Annex I Part I (2)(f)"},
            requirement = "Trustworthy recording of security-relevant activity")
    void a09_controlCharactersCannotForgeLogEntries() throws Exception {
        String forged = "Kitchen\\n2026-12-03T09:00:00Z  INFO AdminController : role ADMIN granted to mallory";

        MockHttpServletResponse response = call(put("/api/devices/{id}/name", ALICE_DEVICE).with(alice())
                .contentType(MediaType.APPLICATION_JSON).content("{\"name\":\"" + forged + "\"}"));

        assertThat(response.getStatus())
                .as("a device name containing a line break was accepted (HTTP %d)", response.getStatus())
                .isEqualTo(400);
    }

    @Test
    @DisplayName("A09 Logging & Alerting Failures – denied access is recorded as a security event")
    @CraRequirement(owasp = "A09:2025 Security Logging & Alerting Failures",
            cra = {"Annex I Part I (2)(l)", "Annex I Part I (2)(d)", "Article 14"},
            requirement = "Record and monitor access; report possible unauthorised access")
    void a09_deniedAccessIsRecorded() throws Exception {
        call(get("/api/devices/{id}", BOB_DEVICE).with(mallory()));

        MockHttpServletResponse events = call(get("/api/admin/security-events").with(admin()));

        assertThat(events.getStatus())
                .as("no security event log (HTTP %d) – you cannot report in 24 h what you never detected", events.getStatus())
                .isEqualTo(200);
        assertThat(events.getContentAsString())
                .as("mallory's access attempt was not recorded")
                .contains("ACCESS_DENIED")
                .contains("mallory");
    }

    // ------------------------------------------------------------------ A10

    @Test
    @DisplayName("A10 Mishandling of Exceptional Conditions – authorisation fails closed")
    @CraRequirement(owasp = "A10:2025 Mishandling of Exceptional Conditions",
            cra = {"Annex I Part I (2)(d)", "Annex I Part I (2)(k)"},
            requirement = "Access control holds under unexpected input; incident impact reduced")
    void a10_authorisationFailsClosed() throws Exception {
        MockHttpServletResponse response = call(post("/api/devices/{id}/commands", ALICE_DEVICE).with(alice())
                .contentType(MediaType.APPLICATION_JSON).content("{\"command\":\"enable_debug_shell\"}"));

        assertThat(response.getStatus())
                .as("a customer opened the debug shell with lower-case input (HTTP %d): %s", response.getStatus(), abbreviate(response))
                .isIn(400, 403);
    }

    @Test
    @DisplayName("A10 Mishandling of Exceptional Conditions – errors do not leak internals")
    @CraRequirement(owasp = "A10:2025 Mishandling of Exceptional Conditions",
            cra = {"Annex I Part I (2)(j)", "Annex I Part I (2)(e)"},
            requirement = "Limit attack surface; no information disclosure")
    void a10_errorsDoNotLeakInternals() throws Exception {
        MockHttpServletResponse response = call(put("/api/devices/{id}/setpoint", ALICE_DEVICE).with(alice())
                .contentType(MediaType.APPLICATION_JSON).content("{\"celsius\": \"warm\"}"));

        assertThat(response.getContentAsString())
                .as("the error response leaks internals: %s", abbreviate(response))
                .doesNotContain("Exception")
                .doesNotContain("\tat ")
                .doesNotContain("demo.thermohub");
    }

    // ------------------------------------------------------------------ beyond the Top 10

    @Test
    @DisplayName("CRA vulnerability handling – a reporting contact is published (security.txt)")
    @CraRequirement(owasp = "Beyond Top 10 (CRA process)",
            cra = {"Annex I Part II (5)", "Annex I Part II (6)"},
            requirement = "Coordinated vulnerability disclosure policy and contact address")
    void cra_vulnerabilityReportingContactIsPublished() throws Exception {
        MockHttpServletResponse response = call(get("/.well-known/security.txt"));

        assertThat(response.getStatus())
                .as("no /.well-known/security.txt (HTTP %d) – researchers do not know where to report", response.getStatus())
                .isEqualTo(200);
        assertThat(response.getContentAsString()).contains("Contact:").contains("Policy:");
    }

    // ------------------------------------------------------------------ helpers

    protected MockHttpServletResponse call(RequestBuilder request) throws Exception {
        return mvc.perform(request).andReturn().getResponse();
    }

    protected static RequestPostProcessor alice() {
        return user("alice").roles("USER");
    }

    protected static RequestPostProcessor mallory() {
        return user("mallory").roles("USER");
    }

    protected static RequestPostProcessor admin() {
        return user("admin").roles("ADMIN");
    }

    private static String abbreviate(MockHttpServletResponse response) throws Exception {
        String body = response.getContentAsString().replace('\n', ' ').replace('\r', ' ');
        return body.length() > 160 ? body.substring(0, 157) + "..." : body;
    }
}
