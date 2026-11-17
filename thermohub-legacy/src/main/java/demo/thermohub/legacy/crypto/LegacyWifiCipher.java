package demo.thermohub.legacy.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.stereotype.Component;

/**
 * A04:2025 Cryptographic Failures – customers' Wi-Fi passwords "encrypted" with a key that is
 * compiled into every build, in ECB mode, without integrity protection. Equal passwords produce
 * equal ciphertexts, and anyone with the JAR has the key.
 */
@Component
public class LegacyWifiCipher {

    private static final byte[] KEY = "ThermoHub2019Key".getBytes(StandardCharsets.US_ASCII);

    public String encrypt(String wifiPassword) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(KEY, "AES"));
            byte[] ciphertext = cipher.doFinal(wifiPassword.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    public String decrypt(String encoded) {
        try {
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(KEY, "AES"));
            return new String(cipher.doFinal(Base64.getDecoder().decode(encoded)), StandardCharsets.UTF_8);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }
}
