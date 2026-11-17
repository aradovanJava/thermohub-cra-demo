package demo.thermohub.cra.crypto;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * A04:2025 fix – AES-256-GCM (authenticated encryption), a fresh 96-bit IV per message, and the
 * device serial bound as associated data so a ciphertext cannot be replayed onto another device.
 * The key is injected from the secret store (THERMOHUB_CRYPTO_WIFI_KEY) – never compiled in.
 * CRA Annex I Part I (2)(e) confidentiality and (2)(f) integrity.
 */
public final class WifiCredentialCipher {

    private static final String TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String FORMAT_VERSION = "v1";
    private static final int IV_BYTES = 12;
    private static final int TAG_BITS = 128;

    private final SecretKey key;
    private final SecureRandom random = new SecureRandom();

    public WifiCredentialCipher(byte[] keyMaterial) {
        if (keyMaterial == null || keyMaterial.length != 32) {
            throw new IllegalArgumentException("A 256-bit key is required");
        }
        this.key = new SecretKeySpec(keyMaterial.clone(), "AES");
    }

    public String encrypt(String plaintext, String deviceSerial) {
        try {
            byte[] iv = new byte[IV_BYTES];
            random.nextBytes(iv);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(deviceSerial.getBytes(StandardCharsets.UTF_8));
            byte[] ciphertext = cipher.doFinal(plaintext.getBytes(StandardCharsets.UTF_8));
            Base64.Encoder b64 = Base64.getEncoder();
            return FORMAT_VERSION + "." + b64.encodeToString(iv) + "." + b64.encodeToString(ciphertext);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Encryption failed", e);
        }
    }

    public String decrypt(String envelope, String deviceSerial) {
        String[] parts = envelope.split("\\.");
        if (parts.length != 3 || !FORMAT_VERSION.equals(parts[0])) {
            throw new IllegalArgumentException("Unsupported ciphertext format");
        }
        try {
            Base64.Decoder b64 = Base64.getDecoder();
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, b64.decode(parts[1])));
            cipher.updateAAD(deviceSerial.getBytes(StandardCharsets.UTF_8));
            return new String(cipher.doFinal(b64.decode(parts[2])), StandardCharsets.UTF_8);
        } catch (AEADBadTagException e) {
            throw new IllegalArgumentException("Ciphertext was modified or belongs to another device", e);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Decryption failed", e);
        }
    }
}
