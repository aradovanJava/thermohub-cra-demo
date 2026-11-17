package demo.thermohub.cra;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.math.BigDecimal;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import demo.thermohub.cra.common.InvalidInputException;
import demo.thermohub.cra.crypto.WifiCredentialCipher;
import demo.thermohub.cra.device.Command;
import demo.thermohub.cra.device.CommandPolicy;
import demo.thermohub.cra.device.CommandPolicy.Decision;
import demo.thermohub.cra.device.DeviceConfigImporter;
import demo.thermohub.cra.device.SearchTerm;
import demo.thermohub.cra.device.Setpoint;
import demo.thermohub.cra.security.AttemptLimiter;
import demo.thermohub.cra.security.PasswordPolicy;
import demo.thermohub.cra.security.Role;

/** Fast unit tests for the plain-Java security building blocks – no Spring context needed. */
class SecurityBuildingBlocksTest {

    @Nested
    @DisplayName("A03 – YAML import")
    class YamlImport {

        private final DeviceConfigImporter importer = new DeviceConfigImporter();

        @Test
        void gadgetTagIsRejectedAndNothingIsCreated() throws Exception {
            Path proof = Path.of("target", "unit-gadget-proof.txt").toAbsolutePath();
            Files.createDirectories(proof.getParent());
            Files.deleteIfExists(proof);
            String gadget = "schedule: !!java.io.FileOutputStream [\"" + proof.toString().replace('\\', '/') + "\"]";

            assertThatThrownBy(() -> importer.parse(gadget)).isInstanceOf(InvalidInputException.class);
            assertThat(proof).doesNotExist();
        }

        @Test
        void aliasBombIsRejected() {
            String laughs = "a: &a [x,x,x,x,x,x,x,x,x,x]\n"
                    + "b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]\n"
                    + "schedule: [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]\n";
            assertThatThrownBy(() -> importer.parse(laughs)).isInstanceOf(InvalidInputException.class);
        }

        @Test
        void unknownSettingIsRejected() {
            assertThatThrownBy(() -> importer.parse("debugShell: true")).isInstanceOf(InvalidInputException.class);
        }

        @Test
        void plainSettingsAreImported() {
            assertThat(importer.parse("ecoMode: true\ndisplayBrightness: 40\n")).containsKeys("ecoMode", "displayBrightness");
        }
    }

    @Nested
    @DisplayName("A04 – Wi-Fi credential encryption")
    class WifiEncryption {

        private final WifiCredentialCipher cipher = newCipher();

        @Test
        void equalPasswordsGiveDifferentCiphertexts() {
            assertThat(cipher.encrypt("Sunflower#2019", "TH-0001")).isNotEqualTo(cipher.encrypt("Sunflower#2019", "TH-0001"));
        }

        @Test
        void ciphertextIsBoundToTheDevice() {
            String envelope = cipher.encrypt("Sunflower#2019", "TH-0001");
            assertThat(cipher.decrypt(envelope, "TH-0001")).isEqualTo("Sunflower#2019");
            assertThatThrownBy(() -> cipher.decrypt(envelope, "TH-0002")).isInstanceOf(IllegalArgumentException.class);
        }

        private static WifiCredentialCipher newCipher() {
            byte[] key = new byte[32];
            new SecureRandom().nextBytes(key);
            return new WifiCredentialCipher(key);
        }
    }

    @Nested
    @DisplayName("A05 / A06 – domain primitives")
    class DomainPrimitives {

        @Test
        void setpointOutsideSafeRangeIsRejected() {
            assertThatThrownBy(() -> new Setpoint(new BigDecimal("95.0"))).isInstanceOf(InvalidInputException.class);
            assertThatThrownBy(() -> new Setpoint(new BigDecimal("4.9"))).isInstanceOf(InvalidInputException.class);
            assertThat(new Setpoint(new BigDecimal("21.54")).celsius()).isEqualByComparingTo("21.5");
        }

        @Test
        void sqlMetacharactersAreNotASearchTerm() {
            assertThatThrownBy(() -> new SearchTerm("%' UNION SELECT 1 -- ")).isInstanceOf(InvalidInputException.class);
            assertThat(new SearchTerm("Living_room").containsPattern()).isEqualTo("%Living\\_room%");
        }
    }

    @Nested
    @DisplayName("A06 / A07 – attempt limiter")
    class Limiter {

        private Instant now = Instant.parse("2026-12-03T09:00:00Z");

        private final Clock clock = new Clock() {
            @Override
            public ZoneId getZone() {
                return ZoneOffset.UTC;
            }

            @Override
            public Clock withZone(ZoneId zone) {
                return this;
            }

            @Override
            public Instant instant() {
                return now;
            }
        };

        @Test
        void blocksAfterFiveFailuresAndRecoversAfterTheWindow() {
            AttemptLimiter limiter = new AttemptLimiter(5, Duration.ofMinutes(15), clock);
            for (int i = 0; i < 4; i++) {
                limiter.recordFailure("login:bob");
            }
            assertThat(limiter.isBlocked("login:bob")).isFalse();
            limiter.recordFailure("login:bob");
            assertThat(limiter.isBlocked("login:bob")).isTrue();
            now = now.plus(Duration.ofMinutes(16));
            assertThat(limiter.isBlocked("login:bob")).isFalse();
        }
    }

    @Nested
    @DisplayName("A07 – password policy")
    class Passwords {

        @Test
        void factoryDefaultsAreRefused() {
            assertThat(PasswordPolicy.violations("admin", "admin")).isNotEmpty();
            assertThat(PasswordPolicy.violations("admin", "")).isNotEmpty();
            assertThatThrownBy(() -> PasswordPolicy.requireCompliant("admin", null, "THERMOHUB_ADMIN_PASSWORD"))
                    .hasMessageContaining("No default credentials");
        }

        @Test
        void longPassphraseIsAccepted() {
            assertThat(PasswordPolicy.violations("admin", "Granite-Harbor-Echo-2026")).isEmpty();
        }
    }

    @Nested
    @DisplayName("A10 – commands fail closed")
    class Commands {

        private final CommandPolicy policy = new CommandPolicy();

        @Test
        void onlyExactCommandNamesParse() {
            assertThatThrownBy(() -> Command.parse("enable_debug_shell")).isInstanceOf(InvalidInputException.class);
            assertThatThrownBy(() -> Command.parse(" REBOOT ")).isInstanceOf(InvalidInputException.class);
            assertThat(Command.parse("REBOOT")).isEqualTo(Command.REBOOT);
        }

        @Test
        void unexpectedInputIsDenied() {
            assertThat(policy.decide(Set.of(Role.USER), Command.ENABLE_DEBUG_SHELL)).isEqualTo(Decision.DENY);
            assertThat(policy.decide(Set.of(), Command.REBOOT)).isEqualTo(Decision.DENY);
            assertThat(policy.decide(null, null)).isEqualTo(Decision.DENY);
            assertThat(policy.decide(Set.of(Role.USER), Command.REBOOT)).isEqualTo(Decision.PERMIT);
        }
    }
}
