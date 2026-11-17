package demo.thermohub.cra.config;

import java.security.SecureRandom;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import demo.thermohub.cra.crypto.SecureTokenGenerator;
import demo.thermohub.cra.crypto.WifiCredentialCipher;
import demo.thermohub.cra.device.CommandPolicy;
import demo.thermohub.cra.device.DeviceConfigImporter;
import demo.thermohub.cra.firmware.FirmwareVerifier;

/**
 * Wires the plain-Java security building blocks. Secrets come from the environment / secret store:
 * THERMOHUB_CRYPTO_WIFI_KEY and THERMOHUB_FIRMWARE_PUBLIC_KEY.
 */
@Configuration
public class ComponentsConfig {

    private static final Logger log = LoggerFactory.getLogger(ComponentsConfig.class);

    @Bean
    WifiCredentialCipher wifiCredentialCipher(@Value("${thermohub.crypto.wifi.key:}") String base64Key,
                                              @Value("${thermohub.demo.enabled:false}") boolean demo) {
        if (base64Key.isBlank()) {
            if (!demo) {
                throw new IllegalStateException("THERMOHUB_CRYPTO_WIFI_KEY (Base64, 256 bit) is required. "
                        + "Keys come from the secret store, never from the repository.");
            }
            log.warn("Demo mode: generated an ephemeral data key – stored Wi-Fi secrets do not survive a restart");
            byte[] ephemeral = new byte[32];
            new SecureRandom().nextBytes(ephemeral);
            return new WifiCredentialCipher(ephemeral);
        }
        return new WifiCredentialCipher(Base64.getDecoder().decode(base64Key.strip()));
    }

    @Bean
    FirmwareVerifier firmwareVerifier(@Value("${thermohub.firmware.public.key:}") String base64PublicKey) {
        FirmwareVerifier verifier = FirmwareVerifier.fromBase64(base64PublicKey);
        if (!verifier.hasTrustAnchor()) {
            log.warn("No firmware signing key configured (THERMOHUB_FIRMWARE_PUBLIC_KEY) – every upload will be rejected");
        }
        return verifier;
    }

    @Bean
    SecureTokenGenerator secureTokenGenerator() {
        return new SecureTokenGenerator();
    }

    @Bean
    CommandPolicy commandPolicy() {
        return new CommandPolicy();
    }

    @Bean
    DeviceConfigImporter deviceConfigImporter() {
        return new DeviceConfigImporter();
    }
}
